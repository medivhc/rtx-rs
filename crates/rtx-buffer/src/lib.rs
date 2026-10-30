#![cfg_attr(not(feature = "std"), no_std)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferError {
    LengthExceedsCapacity,
    InsufficientCapacity,
}

/// Mutable packet storage with explicit length and capacity.
///
/// Protocol crates depend on this contract instead of `Vec<u8>`, `BytesMut`,
/// `Arc<[u8]>`, DMA buffers, or a particular allocator.
pub trait PacketBuf {
    fn capacity(&self) -> usize;
    fn len(&self) -> usize;

    /// Sets the logical length of the initialized region.
    ///
    /// Rejected calls leave the buffer unchanged, so callers can safely retry
    /// or degrade after an error.
    ///
    /// # Errors
    ///
    /// Returns [`BufferError::LengthExceedsCapacity`] when `len` exceeds the
    /// buffer capacity.
    fn set_len(&mut self, len: usize) -> Result<(), BufferError>;

    fn as_slice(&self) -> &[u8];
    fn as_mut_slice(&mut self) -> &mut [u8];

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn remaining_mut(&self) -> usize {
        self.capacity().saturating_sub(self.len())
    }
}

#[derive(Debug)]
pub struct FixedBuf<const N: usize> {
    storage: [u8; N],
    len: usize,
}

impl<const N: usize> FixedBuf<N> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            storage: [0; N],
            len: 0,
        }
    }
}

impl<const N: usize> Default for FixedBuf<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PacketBuf for FixedBuf<N> {
    fn capacity(&self) -> usize {
        N
    }

    fn len(&self) -> usize {
        self.len
    }

    fn set_len(&mut self, len: usize) -> Result<(), BufferError> {
        if len > N {
            return Err(BufferError::LengthExceedsCapacity);
        }
        self.len = len;
        Ok(())
    }

    fn as_slice(&self) -> &[u8] {
        &self.storage[..self.len]
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.storage
    }
}

#[derive(Debug)]
pub struct BorrowedBuf<'a> {
    storage: &'a mut [u8],
    len: usize,
}

impl<'a> BorrowedBuf<'a> {
    pub fn new(storage: &'a mut [u8]) -> Self {
        Self { storage, len: 0 }
    }

    /// Creates a buffer view over `storage` with a pre-set length.
    ///
    /// # Errors
    ///
    /// Returns [`BufferError::LengthExceedsCapacity`] when `len` exceeds
    /// `storage.len()`.
    pub fn with_len(storage: &'a mut [u8], len: usize) -> Result<Self, BufferError> {
        if len > storage.len() {
            return Err(BufferError::LengthExceedsCapacity);
        }
        Ok(Self { storage, len })
    }
}

impl PacketBuf for BorrowedBuf<'_> {
    fn capacity(&self) -> usize {
        self.storage.len()
    }

    fn len(&self) -> usize {
        self.len
    }

    fn set_len(&mut self, len: usize) -> Result<(), BufferError> {
        if len > self.storage.len() {
            return Err(BufferError::LengthExceedsCapacity);
        }
        self.len = len;
        Ok(())
    }

    fn as_slice(&self) -> &[u8] {
        &self.storage[..self.len]
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        self.storage
    }
}

/// Runtime-specific buffer pool. Embedded implementations can return fixed
/// blocks or DMA-backed handles; Linux implementations can wrap slab/arena or
/// registered I/O buffers.
pub trait BufferPool {
    type Buffer: PacketBuf;

    fn acquire(&mut self) -> Option<Self::Buffer>;
    fn release(&mut self, buffer: Self::Buffer);
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    // ---- BUF-ERR ----------------------------------------------------------

    // BUF-ERR-001 — BufferError 变体可构造与比较。
    // `InsufficientCapacity` 为预留契约变体（当前无实现方使用），仍须可构造可比较。
    #[test]
    fn buffer_error_variants_construct_and_compare() {
        let exceeds = BufferError::LengthExceedsCapacity;
        let insufficient = BufferError::InsufficientCapacity;
        assert_ne!(exceeds, insufficient);
        let copied = exceeds; // Copy
        assert_eq!(exceeds, copied);
        assert_ne!(format!("{exceeds:?}"), "");
        assert_ne!(format!("{insufficient:?}"), "");
    }

    // ---- BUF-FIXED --------------------------------------------------------

    const EMPTY_FIXED: FixedBuf<8> = FixedBuf::new();

    // BUF-FIXED-001 — FixedBuf::new/Default 初始状态（含 const 构造）。
    #[test]
    fn fixed_buf_initial_state_is_empty() {
        let buffer = FixedBuf::<8>::new();
        assert_eq!(buffer.capacity(), 8);
        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());
        assert_eq!(buffer.as_slice(), []);
        assert_eq!(buffer.remaining_mut(), 8);

        let defaulted = FixedBuf::<8>::default();
        assert_eq!(defaulted.capacity(), 8);
        assert_eq!(defaulted.len(), 0);
        assert_eq!(defaulted.remaining_mut(), 8);

        // const 构造在编译期完成。
        assert_eq!(EMPTY_FIXED.capacity(), 8);
        assert_eq!(EMPTY_FIXED.len(), 0);
    }

    // BUF-FIXED-002 — set_len 正常路径（0..=N 全部接受）。
    #[test]
    fn fixed_buf_set_len_accepts_zero_through_capacity() {
        let mut buffer = FixedBuf::<8>::new();
        buffer.set_len(4).expect("set_len(4)");
        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.as_slice().len(), 4);
        buffer.set_len(0).expect("set_len(0)");
        assert_eq!(buffer.len(), 0);
        buffer.set_len(8).expect("set_len(8) == capacity");
        assert_eq!(buffer.len(), 8);
    }

    // BUF-FIXED-003 — set_len 超限报错且状态不变。
    #[test]
    fn fixed_buf_set_len_over_capacity_is_rejected_without_side_effects() {
        let mut buffer = FixedBuf::<8>::new();
        buffer.set_len(4).expect("set_len(4)");
        buffer.as_mut_slice()[..4].copy_from_slice(&[1, 2, 3, 4]);

        assert_eq!(buffer.set_len(9), Err(BufferError::LengthExceedsCapacity));
        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.as_slice(), &[1, 2, 3, 4]);

        assert_eq!(
            buffer.set_len(usize::MAX),
            Err(BufferError::LengthExceedsCapacity)
        );
        assert_eq!(buffer.len(), 4);
        assert_eq!(buffer.as_slice(), &[1, 2, 3, 4]);
    }

    // BUF-FIXED-004 — as_slice 只暴露 len（零拷贝读取契约）。
    #[test]
    fn fixed_buf_as_slice_exposes_only_len() {
        let mut buffer = FixedBuf::<8>::new();
        buffer
            .as_mut_slice()
            .copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(buffer.as_slice(), []);
        buffer.set_len(3).expect("set_len(3)");
        assert_eq!(buffer.as_slice(), &[1, 2, 3]);
        buffer.set_len(8).expect("set_len(8)");
        assert_eq!(buffer.as_slice(), &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    // BUF-FIXED-005 — as_mut_slice 全容量可写且经 set_len 可见。
    #[test]
    fn fixed_buf_as_mut_slice_exposes_full_capacity() {
        let mut buffer = FixedBuf::<8>::new();
        buffer.set_len(3).expect("set_len(3)");
        assert_eq!(buffer.as_mut_slice().len(), buffer.capacity());
        buffer.as_mut_slice().fill(0xAA);
        buffer.set_len(5).expect("set_len(5)");
        assert_eq!(buffer.as_slice(), &[0xAA; 5]);
        buffer.set_len(8).expect("set_len(8)");
        assert_eq!(buffer.as_slice(), &[0xAA; 8]);
    }

    // BUF-FIXED-006 — is_empty/remaining_mut 边界。
    #[test]
    fn fixed_buf_is_empty_and_remaining_mut_boundaries() {
        let mut buffer = FixedBuf::<8>::new();
        buffer.set_len(8).expect("full");
        assert!(!buffer.is_empty());
        assert_eq!(buffer.remaining_mut(), 0);
        buffer.set_len(0).expect("empty");
        assert!(buffer.is_empty());
        assert_eq!(buffer.remaining_mut(), 8);
        buffer.set_len(4).expect("half");
        assert_eq!(buffer.remaining_mut(), 4);
    }

    // BUF-FIXED-007 — FixedBuf<0> 零容量边界。
    #[test]
    fn fixed_buf_zero_capacity_is_usable() {
        let mut buffer = FixedBuf::<0>::new();
        assert_eq!(buffer.capacity(), 0);
        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());
        assert_eq!(buffer.remaining_mut(), 0);
        buffer
            .set_len(0)
            .expect("set_len(0) on zero-capacity buffer");
        assert_eq!(buffer.set_len(1), Err(BufferError::LengthExceedsCapacity));
        assert_eq!(buffer.as_mut_slice(), []);
    }

    // ---- BUF-BORROWED -----------------------------------------------------

    // BUF-BORROWED-001 — BorrowedBuf::new 初始状态不暴露既有内容。
    #[test]
    fn borrowed_buf_new_starts_empty() {
        let mut storage = [0x5Au8; 16];
        let buffer = BorrowedBuf::new(&mut storage);
        assert_eq!(buffer.capacity(), 16);
        assert_eq!(buffer.len(), 0);
        assert!(buffer.is_empty());
        assert_eq!(buffer.as_slice(), []);
    }

    // BUF-BORROWED-002 — with_len 正常、边界与超限。
    #[test]
    fn borrowed_buf_with_len_accepts_up_to_storage_len() {
        let mut storage = [0x11u8; 16];
        {
            let buffer = BorrowedBuf::with_len(&mut storage, 4).expect("with_len(4)");
            assert_eq!(buffer.len(), 4);
            assert_eq!(buffer.as_slice(), &[0x11; 4]);
        }
        {
            let buffer = BorrowedBuf::with_len(&mut storage, 16).expect("with_len(16) == storage");
            assert_eq!(buffer.len(), 16);
            assert_eq!(buffer.as_slice(), &[0x11; 16]);
        }
        assert_eq!(
            BorrowedBuf::with_len(&mut storage, 17).unwrap_err(),
            BufferError::LengthExceedsCapacity
        );

        let mut empty: [u8; 0] = [];
        {
            let buffer =
                BorrowedBuf::with_len(&mut empty, 0).expect("with_len(0) on empty storage");
            assert_eq!(buffer.len(), 0);
        }
        assert_eq!(
            BorrowedBuf::with_len(&mut empty, 1).unwrap_err(),
            BufferError::LengthExceedsCapacity
        );
    }

    // BUF-BORROWED-003 — BorrowedBuf 的 PacketBuf 行为与 FixedBuf 对齐。
    #[test]
    fn borrowed_buf_packet_buf_behavior_matches_fixed_buf() {
        let mut storage = [0u8; 16];
        let mut buffer = BorrowedBuf::new(&mut storage);
        buffer.set_len(5).expect("set_len(5)");
        assert_eq!(buffer.len(), 5);
        buffer.set_len(16).expect("set_len(16) == capacity");
        assert_eq!(buffer.len(), 16);
        assert_eq!(
            buffer.set_len(17).unwrap_err(),
            BufferError::LengthExceedsCapacity
        );
        assert_eq!(buffer.len(), 16); // 错误无副作用
        buffer.set_len(0).expect("set_len(0)");
        assert_eq!(buffer.as_mut_slice().len(), 16); // 全 storage
        buffer.as_mut_slice()[..3].copy_from_slice(&[7, 8, 9]);
        buffer.set_len(3).expect("set_len(3)");
        assert_eq!(buffer.as_slice(), &[7, 8, 9]);
    }

    // BUF-BORROWED-004 — BorrowedBuf 借用生命周期（编译期契约）。
    // 记录（不进入编译）：同一 storage 上两个 BorrowedBuf 并存应被借用检查器拒绝。
    #[test]
    fn borrowed_buf_releases_storage_when_dropped() {
        let mut storage = [0u8; 8];
        {
            let mut buffer = BorrowedBuf::new(&mut storage);
            buffer.set_len(4).expect("set_len(4)");
            assert_eq!(buffer.len(), 4);
        }
        // buffer 已 drop：storage 的可变借用被释放，可再次写入。
        storage[0] = 0xFF;
        assert_eq!(storage[0], 0xFF);
    }

    // ---- BUF-POOL ---------------------------------------------------------

    // BUF-POOL-001 支撑 mock：故意违反 len <= capacity 的探测缓冲。
    struct OddBuf;

    impl PacketBuf for OddBuf {
        fn capacity(&self) -> usize {
            4
        }

        fn len(&self) -> usize {
            8 // 故意大于 capacity，探测默认方法的饱和语义
        }

        fn set_len(&mut self, _len: usize) -> Result<(), BufferError> {
            Ok(())
        }

        fn as_slice(&self) -> &[u8] {
            &[]
        }

        fn as_mut_slice(&mut self) -> &mut [u8] {
            &mut []
        }
    }

    // BUF-POOL-001 — PacketBuf 默认方法的 saturating 语义。
    #[test]
    fn packet_buf_default_methods_are_saturating() {
        let buffer = OddBuf;
        assert_eq!(buffer.remaining_mut(), 0); // saturating_sub 不回绕
        assert!(!buffer.is_empty());
    }

    // BUF-POOL-002/003 支撑 mock：固定块池。
    #[derive(Debug)]
    struct FixedBlockPool<const SLOTS: usize> {
        blocks: [Option<FixedBuf<64>>; SLOTS],
        dropped: usize,
    }

    impl<const SLOTS: usize> FixedBlockPool<SLOTS> {
        fn new() -> Self {
            Self {
                blocks: core::array::from_fn(|_| Some(FixedBuf::new())),
                dropped: 0,
            }
        }
    }

    impl<const SLOTS: usize> BufferPool for FixedBlockPool<SLOTS> {
        type Buffer = FixedBuf<64>;

        fn acquire(&mut self) -> Option<Self::Buffer> {
            self.blocks.iter_mut().find_map(Option::take)
        }

        fn release(&mut self, mut buffer: Self::Buffer) {
            // mock 约定：回收即重置，池中 buffer 恒为 len = 0。
            buffer
                .set_len(0)
                .expect("reset released buffer to zero length");
            if let Some(slot) = self.blocks.iter_mut().find(|slot| slot.is_none()) {
                *slot = Some(buffer);
            } else {
                // mock 约定：槽满时丢弃并记账，不 panic。
                self.dropped += 1;
            }
        }
    }

    // BUF-POOL-002 — BufferPool 固定块池 acquire/release 往返。
    #[test]
    fn fixed_block_pool_acquire_release_roundtrip() {
        let mut pool = FixedBlockPool::<2>::new();

        let mut first = pool.acquire().expect("first acquire");
        assert_eq!(first.len(), 0);
        first.as_mut_slice()[..10].fill(0x5A);
        first.set_len(10).expect("publish 10 bytes");
        assert_eq!(first.len(), 10);
        pool.release(first); // 两块归位，池满

        // 向已满池 release：丢弃并记账，不 panic。
        let mut extra = FixedBuf::<64>::new();
        extra.set_len(1).expect("set_len(1)");
        pool.release(extra);
        assert_eq!(pool.dropped, 1);

        // 回收复用：再取出的块已重置，旧内容不可见。
        let second = pool.acquire().expect("second acquire");
        assert_eq!(second.len(), 0); // 回收即重置
        assert_eq!(second.as_slice(), []); // 旧内容不可见

        // 耗尽：两个槽均已取出，第三次 acquire 返回 None。
        let third = pool.acquire().expect("third acquire");
        assert!(pool.acquire().is_none());

        // 归还一块后再 acquire 成功。
        pool.release(second);
        assert!(pool.acquire().is_some());
        pool.release(third);
    }

    // BUF-POOL-003 支撑 mock：BorrowedBuf 单发池与泛型消费函数。
    fn use_pool<P: BufferPool>(pool: &mut P) -> Option<usize> {
        let buffer = pool.acquire()?;
        let capacity = buffer.capacity();
        pool.release(buffer);
        Some(capacity)
    }

    #[derive(Debug)]
    struct BorrowedBufPool<'a> {
        storage: Option<&'a mut [u8]>,
    }

    impl<'a> BufferPool for BorrowedBufPool<'a> {
        type Buffer = BorrowedBuf<'a>;

        fn acquire(&mut self) -> Option<Self::Buffer> {
            let storage = self.storage.take()?;
            Some(BorrowedBuf::new(storage))
        }

        fn release(&mut self, _buffer: Self::Buffer) {
            // 安全 mock 无法从返回的 buffer 取回借用；参数在返回时 drop（单发池）。
        }
    }

    // BUF-POOL-003 — BufferPool 关联类型约束编译期验证。
    #[test]
    fn buffer_pool_associated_type_bound_compiles() {
        let mut fixed_pool = FixedBlockPool::<2>::new();
        assert_eq!(use_pool(&mut fixed_pool), Some(64));

        let mut storage = [0u8; 32];
        let mut borrowed_pool = BorrowedBufPool {
            storage: Some(&mut storage),
        };
        assert_eq!(use_pool(&mut borrowed_pool), Some(32));
    }
}
