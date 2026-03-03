#![no_std]
#![no_main]
use core::mem::{self, offset_of};

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::DevMapHash,
    programs::XdpContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
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
    let ether_type_ptr: *const EtherType = ptr_at(&ctx, offset_of!(EthHdr, ether_type))?;
    match unsafe { *ether_type_ptr } {
        EtherType::Ipv4 => (),
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4_proto_ptr: *const IpProto = ptr_at(&ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, proto))?;
    let dest_addr_ptr: *const [u8; 4] = ptr_at(&ctx, EthHdr::LEN + offset_of!(Ipv4Hdr, dst_addr))?;

    let dest_addr = u32::from_be_bytes(unsafe { *dest_addr_ptr });

    match unsafe { *ipv4_proto_ptr } {
        IpProto::Udp | IpProto::Tcp | IpProto::Icmp => match REDIRECT_MAP.redirect(dest_addr, 2) {
            Ok(xdp_code) => Ok(xdp_code),
            Err(xdp_code) => Ok(xdp_code),
        },
        _ => Ok(xdp_action::XDP_PASS),
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
