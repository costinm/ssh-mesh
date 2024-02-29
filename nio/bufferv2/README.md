# GVisor bufferv2

GVisor discovered that memory copy slows down operations - and switched to a new reference counted 
model and lists of buffers. This is a fork, cleaned up of dependencies.

The intent is to use it in the io utils and h2 implementation.

The model: 

Buffer is a linked list of "View"
- Prepend/Append
- PullUp - makes a range contiguous
- Flatten - one large buffer
- Clone - copy on write, chunks shared until written to
- Apply(fn)
- Merge
- WriteFromReader - multiple reads of 64k
- ReadToWriter - pushes chunks to writer
- AsBufferReader, 

View:
- has Next/Prev
- a 'chunk' containing data 
- a reference count.
- read and write
- NewView gets a view from the view pool and a chunk.
- NewViewSize - also calls Grow(n), which adds to 'write' (==end)
- Reader, Writer
- AsSlice - no copy but 'should not modify directly', instead Write(At)
- ToSlice - a copy 
- Clone - reused chunk, different read/write. Most call Release()
- Reset - set read/write to 0
- 

## History 

Forked from ce87948214909bcf7d274d9dc8f0772829d21d2a on Dec 12.

- use std log, context, atomic instead of the gvisor extensions
- still using MostSignificantOne64 in assembly for getChunkPool - can be rewritten
- removed ref leak checking and associated dependency
