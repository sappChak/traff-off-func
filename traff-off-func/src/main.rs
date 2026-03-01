use std::net::Ipv4Addr;

use anyhow::Context as _;
use aya::{
    maps::DevMapHash,
    programs::{Xdp, XdpFlags},
};
use clap::Parser;
use futures::StreamExt;

use log::warn;
use docker_api::{
    Docker,
    conn::TtyChunk,
    opts::{ExecCreateOpts, ExecStartOpts},
};
use nix::net::if_::if_nameindex;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[arg(short, long, default_value = "docker0")]
    network: String,
}

struct ContainerInfo {
    name: String,
    veth: String,
    ipv4: Ipv4Addr,
    ifindex: u32,
}

async fn get_container_infos(network: &str) -> anyhow::Result<Vec<ContainerInfo>> {
    let mut container_infos = vec![];
    let docker: Docker = Docker::unix("/var/run/docker.sock");
    let network = docker.networks().get(network).inspect().await?;

    println!("{:?}", network);

    if let Some(containers) = network.containers {
        for (cid, container_info) in &containers {
            let exec_opts = ExecCreateOpts::builder()
                .command(vec!["cat", "/sys/class/net/eth0/iflink"])
                .attach_stdout(true)
                .attach_stderr(true)
                .build();

            let container = docker.containers().get(cid);

            println!("{:?}", container);

            let mut exec_stream = container
                .exec(&exec_opts, &ExecStartOpts::default())
                .await?;

            while let Some(result) = exec_stream.next().await {
                match result {
                    Ok(chunks) => match chunks {
                        TtyChunk::StdOut(items) => {
                            let output = String::from_utf8_lossy(&items);
                            let iflink: u32 = output.trim().parse::<u32>().unwrap();

                            let interfaces = if_nameindex()?;

                            for interface in &interfaces {
                                if interface.index() == iflink {
                                    println!("interface name: {:?}", interface.name());
                                    let name = container_info.name.clone().unwrap();
                                    let veth = interface.name().to_string_lossy().to_string();
                                    println!("ip: {:?}", container_info.i_pv_4_address);
                                    let ipv4 = container_info
                                        .i_pv_4_address
                                        .as_ref()
                                        .unwrap()
                                        .split('/')
                                        .next()
                                        .unwrap()
                                        .parse()
                                        .unwrap();
                                    container_infos.push(ContainerInfo {
                                        name,
                                        veth,
                                        ipv4,
                                        ifindex: iflink,
                                    });
                                    break;
                                }
                            }
                        }
                        TtyChunk::StdErr(items) => {
                            let error = String::from_utf8_lossy(&items);
                            println!("Error inside container: {error}")
                        }
                        TtyChunk::StdIn(_) => {}
                    },
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }
        }
    }

    Ok(container_infos)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    println!("Passed opts: {:?}", opt);

    env_logger::init();

    let mut ebpf: aya::Ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/traff-off-func"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { network } = opt;

    let program: &mut Xdp = ebpf.program_mut("xdp_redirect").unwrap().try_into()?;
    program.load()?;

    let containers = get_container_infos(&network).await?;

    let mut links = Vec::new();
    for container in &containers {
        println!(
            "attaching xdp program to: {}, ifindex: {} of container {}",
            container.veth, container.ifindex, container.name
        );
        let link = program.attach(&container.veth, XdpFlags::SKB_MODE) 
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
        links.push(link);
    }

    assert_eq!(links.len(), containers.len());

    let mut devmap = DevMapHash::try_from(ebpf.map_mut("REDIRECT_MAP").unwrap())?;
    for container in containers {
        println!(
            "inserting a pair into devmap: <{:?},{}>",
            container.ipv4, container.ifindex
        );
        let _ = devmap.insert(u32::from(container.ipv4), container.ifindex, None, 0);
    }

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
