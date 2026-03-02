#![no_std]
#![no_main]
use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::DevMapHash,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[map(name = "REDIRECT_MAP")]
static REDIRECT_MAP: DevMapHash = DevMapHash::with_max_entries(32, 0);

#[xdp]
pub fn xdp_redirect(ctx: XdpContext) -> u32 {
    match try_xdp_redirect(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[xdp]
pub fn xdp_pass(_ctx: XdpContext) -> u32 {
    xdp_action::XDP_PASS
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start: usize = ctx.data();
    let end: usize = ctx.data_end();
    let len: usize = mem::size_of::<T>();

    if start + len + offset > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_xdp_redirect(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => (),
        _ => return Ok(xdp_action::XDP_PASS),
    }
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;

    let destination_address: u32 = u32::from_be_bytes(unsafe { (*ipv4hdr).dst_addr });

    match unsafe { (*ipv4hdr).proto } {
        network_types::ip::IpProto::Udp | network_types::ip::IpProto::Icmp => {
            info!(
                &ctx,
                "redirecting towards destination address: {:i}", destination_address
            );
            match REDIRECT_MAP.redirect(destination_address, 0) {
                Ok(xdp_code) => Ok(xdp_code),
                Err(xdp_code) => Ok(xdp_code),
            }
        }
        _ => Ok(xdp_action::XDP_PASS), // TCP logic is implemented in the kernel
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
