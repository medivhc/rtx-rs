//! `M3-H1` evidence: QUIC varint boundaries, truncation and overflow
//! rejection, and a real allocation count for one representative decode.
//!
//! The allocation counter is an actual global allocator: it wraps
//! `std::alloc::System` and increments a thread-local `Cell<usize>` for every
//! allocation made by the thread that enabled counting. The enable flag and the
//! counter live in the same thread-local scope, so allocations made by other
//! tests can never enter the measurement window. `m3_h1_no_alloc` therefore
//! observes the allocator itself rather than merely asserting an API shape.

#![allow(unsafe_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use rtx_wire::varint::{self, MAX_VARINT, VarInt};
use rtx_wire::{Decode, Encode, WireError};

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

#[allow(unsafe_code)]
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.try_with(Cell::get).unwrap_or(false) {
            ALLOCATIONS
                .try_with(|allocations| allocations.set(allocations.get() + 1))
                .unwrap_or(());
        }
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL_ALLOCATOR: CountingAllocator = CountingAllocator;

/// Runs `operation` with counting enabled and returns its result together with
/// the number of allocations the calling thread made in that window.
fn counted_allocations<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    // Counting and the counter share one thread-local scope, so a concurrent
    // test's allocations cannot leak into this window.
    COUNTING.with(|counting| counting.set(false));
    let base = ALLOCATIONS.with(Cell::get);
    COUNTING.with(|counting| counting.set(true));
    let value = operation();
    COUNTING.with(|counting| counting.set(false));
    (value, ALLOCATIONS.with(Cell::get) - base)
}

#[test]
fn m3_h1_boundary_round_trip() {
    let cases = [
        (0u64, 1usize),
        (63, 1),
        (64, 2),
        (16_383, 2),
        (16_384, 4),
        ((1 << 30) - 1, 4),
        (1 << 30, 8),
        (MAX_VARINT, 8),
    ];
    for (value, expected_len) in cases {
        let mut buffer = [0u8; 8];
        let written = varint::encode(value, &mut buffer).expect("encode varint");
        assert_eq!(written, expected_len, "value {value}");
        assert_eq!(varint::encoded_len(value), expected_len, "value {value}");

        let (decoded, consumed) = varint::decode(&buffer[..written]).expect("decode varint");
        assert_eq!(decoded, value);
        assert_eq!(consumed, written);

        // The `Encode`/`Decode` trait shape produces the same wire bytes.
        let wrapped = VarInt::new(value).expect("valid varint");
        assert_eq!(wrapped.get(), value);
        assert_eq!(Encode::encoded_len(&wrapped), expected_len);
        let mut trait_buffer = [0u8; 8];
        let trait_written = wrapped.encode(&mut trait_buffer).expect("encode trait");
        assert_eq!(trait_written, expected_len);
        assert_eq!(trait_buffer[..trait_written], buffer[..written]);
        let (decoded, consumed) =
            VarInt::decode(&trait_buffer[..trait_written]).expect("decode trait");
        assert_eq!(decoded, wrapped);
        assert_eq!(consumed, trait_written);
    }

    // Non-minimal encodings are accepted (`RFC 9000` section 16).
    assert_eq!(varint::decode(&[0x80, 0x00, 0x00, 0x00]), Ok((0, 4)));
    assert_eq!(varint::decode(&[0x40, 0x00]), Ok((0, 2)));
    assert_eq!(varint::decode(&[0xFF; 8]), Ok((MAX_VARINT, 8)));
    // Trailing bytes belong to the caller; only the varint is consumed.
    assert_eq!(varint::decode(&[0x3F, 0xAA]), Ok((63, 1)));
}

#[test]
fn m3_h1_truncated_rejected() {
    let truncated: [&[u8]; 5] = [
        &[],
        &[0x40],
        &[0x80, 0x00],
        &[0x80, 0x00, 0x00],
        &[0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    ];
    for input in truncated {
        assert_eq!(
            varint::decode(input),
            Err(WireError::UnexpectedEnd),
            "input {input:?}"
        );
        assert_eq!(
            VarInt::decode(input),
            Err(WireError::UnexpectedEnd),
            "input {input:?}"
        );
    }
}

#[test]
fn m3_h1_overflow_rejected() {
    let too_large = MAX_VARINT + 1;
    assert_eq!(VarInt::new(too_large), Err(WireError::InvalidValue));
    assert_eq!(VarInt::new(u64::MAX), Err(WireError::InvalidValue));
    assert_eq!(varint::encoded_len(too_large), 8);

    let mut buffer = [0u8; 8];
    assert_eq!(
        varint::encode(too_large, &mut buffer),
        Err(WireError::InvalidValue)
    );
    assert_eq!(
        varint::encode(u64::MAX, &mut buffer),
        Err(WireError::InvalidValue)
    );
    // The bound itself is accepted and needs the full 8-byte width.
    assert_eq!(varint::encode(MAX_VARINT, &mut buffer), Ok(8));
    assert_eq!(
        VarInt::new(MAX_VARINT)
            .expect("max is valid")
            .encode(&mut [0u8; 4]),
        Err(WireError::OutputTooSmall)
    );

    // A short output buffer is rejected without a partial write.
    let mut small = [0u8; 1];
    assert_eq!(
        varint::encode(64, &mut small),
        Err(WireError::OutputTooSmall)
    );
    assert_eq!(
        varint::encode(0xFF, &mut small),
        Err(WireError::OutputTooSmall)
    );
    assert_eq!(varint::encode(63, &mut small), Ok(1));
}

#[test]
fn m3_h1_no_alloc() {
    // Widest representative decode: `[0xFF; 8]` is `MAX_VARINT` in 8 bytes.
    let input = [0xFFu8; 8];
    let (decoded, allocations) = counted_allocations(|| varint::decode(&input));
    assert_eq!(allocations, 0, "varint::decode must not allocate");
    assert_eq!(decoded, Ok((MAX_VARINT, 8)));

    // Narrow path through the `Decode` trait.
    let byte = [0x3Fu8];
    let (decoded, allocations) = counted_allocations(|| VarInt::decode(&byte));
    assert_eq!(allocations, 0, "VarInt::decode must not allocate");
    assert_eq!(decoded.expect("decode 63").0.get(), 63);
}

/// Positive control: the same counter observes a real heap allocation, so the
/// zero counts above are a measurement rather than a counter that never fires.
#[test]
fn allocation_counter_observes_real_allocations() {
    let (value, allocations) = counted_allocations(|| Box::new(42u64));
    assert_eq!(allocations, 1, "Box::new performs exactly one allocation");
    assert_eq!(*value, 42);
}
