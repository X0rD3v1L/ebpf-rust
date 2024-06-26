#![no_std]
#![no_main]

use aya_ebpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
fn data_at(ctx: &XdpContext, offset: usize, len: usize) -> Result<*const u8, ()> {
    let start = ctx.data();
    let end = ctx.data_end();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const u8)
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });

    let (source_port, is_http) = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let source_port = u16::from_be(unsafe { (*tcphdr).source });
            let dest_port = u16::from_be(unsafe { (*tcphdr).dest });
            let is_http = dest_port == 80;
            if is_http {
                let payload_offset = EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN;
                if let Ok(payload_ptr) = data_at(&ctx, payload_offset, 4) {
                    let payload = unsafe { core::slice::from_raw_parts(payload_ptr, 4) };
                    if payload == b"GET " || payload == b"POST" || payload == b"HEAD" || payload == b"PUT " || payload == b"DELE" {
                        info!(&ctx, "HTTP Request detected from IP: {:i}, PORT: {} DEST PORT: {}", source_addr, source_port,dest_port);
                        return Ok(xdp_action::XDP_DROP);
                    }
                } else {
                    info!(&ctx, "Failed to read HTTP payload from IP: {:i}, PORT: {}", source_addr, source_port);
                }
            }

            (source_port, is_http)
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            let source_port = u16::from_be(unsafe { (*udphdr).source });
            (source_port, false)
        }
        _ => return Err(()),
    };

    if !is_http && source_port == 443 {
        info!(&ctx, "SRC IP: {:i}, SRC PORT: {}", source_addr, source_port);
    }

    Ok(xdp_action::XDP_PASS)
}
