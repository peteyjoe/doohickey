//! RP2350 flash-CS BOOTSEL input, sampled only by the core-0 application owner.
//! Backport of Embassy's RP235x reader (MIT/Apache-2.0):
//! https://github.com/embassy-rs/embassy/blob/main/embassy-rp/src/bootsel.rs
//! Embassy 0.10.0 exposes its reader only for RP2040. Match its flash::in_ram
//! exclusion here using public APIs; never treat QSPI CS as an ordinary input.
use embassy_rp::{Peri, pac, peripherals::BOOTSEL};

pub struct Button<'d> {
    _peripheral: Peri<'d, BOOTSEL>,
}
impl<'d> Button<'d> {
    pub fn new(peripheral: Peri<'d, BOOTSEL>) -> Self {
        Self {
            _peripheral: peripheral,
        }
    }
    pub fn pressed(&mut self) -> bool {
        assert_eq!(
            pac::SIO.cpuid().read(),
            0,
            "BOOTSEL must be sampled on core 0"
        );
        let mut ctrl = pac::io::regs::GpioCtrl::default();
        ctrl.set_oeover(pac::io::vals::Oeover::DISABLE);
        // RP2350 QSPI SS is index 3 (RP2040 uses index 1).
        let cs = pac::IO_QSPI.gpio(3).as_ptr();
        embassy_rp::multicore::pause_core1();
        let status = critical_section::with(|_| {
            // No interrupt may start a new DMA/XIP transfer after these waits.
            for n in 0..16 {
                let ch = pac::DMA.ch(n);
                while ch.read_addr().read() < 0x2000_0000 && ch.ctrl_trig().read().busy() {
                    core::hint::spin_loop();
                }
            }
            while pac::XIP_CTRL.stream_ctr().read().0 > 0 {
                core::hint::spin_loop();
            }
            // SAFETY: core 1 paused, interrupts excluded, flash DMA/XIP idle.
            // The RAM-only helper restores CS before returning to flash code.
            unsafe { read_cs(cs.cast(), ctrl.0) }
        });
        embassy_rp::multicore::resume_core1();
        !pac::io::regs::GpioStatus(status).infrompad()
    }
}

#[inline(never)]
#[unsafe(link_section = ".data.ram_func")]
unsafe fn read_cs(cs: *mut u32, disabled_ctrl: u32) -> u32 {
    let status: u32;
    // No calls, stack accesses or flash constants while CS is tri-stated.
    unsafe {
        core::arch::asm!(
            "ldr {original}, [{cs}, #4]",
            "str {value}, [{cs}, #4]",
            "2:",
            "subs {delay}, #8",
            "bne 2b",
            "ldr {value}, [{cs}]",
            "str {original}, [{cs}, #4]",
            cs = in(reg) cs,
            original = out(reg) _,
            value = inout(reg) disabled_ctrl => status,
            delay = inout(reg) 8192u32 => _,
            options(nostack),
        );
    }
    status
}
