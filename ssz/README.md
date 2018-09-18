# simpleserialize (ssz) [WIP]

This is currently a ***Work In Progress*** crate.


SimpleSerialize is a serialization protocol described by Vitalik Buterin. The
method is tentatively intended for use in the Ethereum Beacon Chain as
described in the [Ethereum 2.1 Spec](https://notes.ethereum.org/s/Syj3QZSxm).

There are two primary sources for this spec, and they are presently
conflicting:

 - The ethereum/beacon_chain reference implementation [simpleserialize.py](https://github.com/ethereum/beacon_chain/blob/master/beacon_chain/utils/simpleserialize.py) file.
 - The [py_ssz module](https://github.com/ethereum/research/tree/master/py_ssz)
   in ethereum/research.

This implementation is presently a placeholder until the final spec is decided.
Do not rely upon it for reference.


## Table of Contents

* [SimpleSerialize Overview](#simpleserialize-overview)
  + [Serialize/Encode](#serializeencode)
    - [int or uint: 8/16/24/32/64/256](#int-or-uint-816243264256)
    - [Address](#address)
    - [Hash32](#hash32)
    - [Bytes](#bytes)
    - [List](#list)
  + [Deserialize/Decode](#deserializedecode)
    - [Int or Uint: 8/16/24/32/64/256](#int-or-uint-816243264256)
    - [Address](#address-1)
    - [Hash32](#hash32-1)
    - [Bytes](#bytes-1)
    - [List](#list-1)
* [Technical Overview](#technical-overview)
* [Building](#building)
  + [Installing Rust](#installing-rust)
* [Dependencies](#dependencies)
  + [bytes v0.4.9](#bytes-v049)
  + [ethereum-types](#ethereum-types)
* [Interface](#interface)
  + [Encodable](#encodable)
  + [SszStream](#sszstream)
    - [new()](#new)
    - [append(&mut self, value: &E) -> &mut Self](#appendmut-self-value-e---mut-self)
    - [append_encoded_val(&mut self, vec: &Vec)](#append_encoded_valmut-self-vec-vec)
    - [append_vec(&mut self, vec: &Vec)](#append_vecmut-self-vec-vec)
    - [drain(self) -> Vec](#drainself---vec)
* [Usage](#usage)
  + [Serializing/Encoding](#serializingencoding)
    - [Rust](#rust)

### TODO

 * [ ] Wait for spec to finalize.
 * [ ] Implement encoding for all useful types.
 * [ ] Implement decoding.

---

## SimpleSerialize Overview

The ``simpleserialize`` method for serialization follows simple byte conversion,
making it effective and efficient for encoding and decoding.

The decoding requires knowledge of the data **type** and the order of the
serialization.

Syntax:

| Shorthand    | Meaning                                             |
|:-------------|:----------------------------------------------------|
| `big`        | ``big endian``                                      |
| `to_bytes`   | convert to bytes. Params: ``(size, byte order)``    |
| `from_bytes` | convert from bytes. Params: ``(bytes, byte order)`` |
| `value`      | the value to serialize                              |
| `rawbytes`   | raw encoded/serialized bytes                        |
| `len(value)` | get the length of the value. (number of bytes etc)  |

### Serialize/Encode

#### int or uint: 8/16/24/32/64/256

Convert directly to bytes the size of the int. (e.g. ``int16 = 2 bytes``)

| Check to perform       | Code                    |
|:-----------------------|:------------------------|
| Int size is not 0      | ``int_size > 0``        |
| Size is a byte integer | ``int_size % 8 == 0``   |
| Value is less than max | ``2**int_size > value`` |

```
buffer_size = int_size / 8
return value.to_bytes(buffer_size, 'big')
```

#### Address

The address should already come as a hash/byte format. Ensure that length is
**20**.

| Check to perform       | Code                 |
|:-----------------------|:---------------------|
| Length is correct (20) | ``len(value) == 20`` |

```
assert( len(value) == 20 )
return value
```

#### Hash32

The hash32 should already be a 32 byte length serialized data format. The safety
check ensures the 32 byte length is satisfied.

| Check to perform       | Code                 |
|:-----------------------|:---------------------|
| Length is correct (32) | ``len(value) == 32`` |

```
assert( len(value) == 32 )
return value
```

#### Bytes

For general `byte` type:
1. Get the length/number of bytes; Encode into a 4byte integer.
2. Append the value to the length and return: ``[ length_bytes ] + [
   value_bytes ]``

```
byte_length = (len(value)).to_bytes(4, 'big')
return byte_length + value
```

#### List

For lists of values, get the length of the list and then serialize the value
of each item in the list:
1. For each item in list:
   1. serialize.
   2. append to string.
2. Get size of serialized string. Encode into a 4 byte integer.

```
serialized_list_string = ''

for item in value:
   serialized_list_string += serialize(item)

serialized_len = len(serialized_list_string)

return serialized_len + serialized_list_string
```

### Deserialize/Decode

The decoding requires knowledge of the type of the item to be decoded. When
performing decoding on an entire serialized string, it also requires knowledge
of what order the objects have been serialized in.

Note: Each return will provide ``deserialized_object, new_index`` keeping track
of the new index.

At each step, the following checks should be made:

| Check Type               | Check                                                     |
|:-------------------------|:----------------------------------------------------------|
| Ensure sufficient length | ``length(rawbytes) > current_index + deserialize_length`` |

#### Int or Uint: 8/16/24/32/64/256

Convert directly from bytes into integer utilising the number of bytes the same
size as the integer length. (e.g. ``int16 == 2 bytes``)

```
byte_length = int_size / 8
new_index = current_index + int_size
return int.from_bytes(rawbytes[current_index:current_index+int_size], 'big'), new_index
```

#### Address

Return the 20 bytes.

```
new_index = current_index + 20
return rawbytes[current_index:current_index+20], new_index
```

#### Hash32

Return the 32 bytes.

```
new_index = current_index + 32
return rawbytes[current_index:current_index+32], new_index
```

#### Bytes

Get the length of the bytes, return the bytes.

```
bytes_length = int.from_bytes(rawbytes[current_index:current_index+4], 'big')
new_index = current_index + 4 + bytes_lenth
return rawbytes[current_index+4:current_index+4+bytes_length], new_index
```

#### List

1. Get the length of the serialized list bytes.
2. Loop through the bytes;
   1. Deserialize the object with that length.
   2. Keep track of current position

Note Before: there are a number of checks to be performed, ensuring there is
enough room left.

| Check type                          | code                                  |
|:------------------------------------|:--------------------------------------|
| rawbytes has enough left for length | ``len(rawbytes) > current_index + 4`` |

```
total_length = int.from_bytes(rawbytes[current_index:current_index+4], 'big')
new_index = current_index + 4 + total_length
item_index = current_index + 4
deserialized_list = []

while item_index < new_index:
   object, item_index = deserialize(rawbytes, item_index, item_type)
   deserialized_list.append(object)

return deserialized_list, new_index
```

## Technical Overview

The SimpleSerialize is a simple method for serializing objects for use in the
Ethereum beacon chain proposed by Vitalik Buterin. There are currently two
implementations denoting the functionality, the [Reference
Implementation](https://github.com/ethereum/beacon_chain/blob/master/beacon_chain/utils/simpleserialize.py)
and the [Module](https://github.com/ethereum/research/tree/master/py_ssz) in
Ethereum research. It is being developed as a crate for the [**Rust programming
language**](https://www.rust-lang.org).

The crate will provide the functionality to serialize several types in
accordance with the spec and provide a serialized stream of bytes.

## Building

ssz currently builds on **rust v1.27.1**

### Installing Rust

The [**Rustup**](https://rustup.rs/) tool provides functionality to easily
manage rust on your local instance. It is a recommended method for installing
rust.

Installing on Linux or OSX:

```
curl https://sh.rustup.rs -sSf | sh
```

Installing on Windows:

* 32 Bit: [ https://win.rustup.rs/i686 ](https://win.rustup.rs/i686)
* 64 Bit: [ https://win.rustup.rs/x86_64 ](https://win.rustup.rs/x86_64)

## Dependencies

All dependencies are listed in the ``Cargo.toml`` file.

To build and install all related dependencies:

```
cargo build
```

### bytes v0.4.9

The `bytes` crate provides effective Byte Buffer implementations and
interfaces.

Documentation: [ https://docs.rs/bytes/0.4.9/bytes/ ](https://docs.rs/bytes/0.4.9/bytes/)

### ethereum-types

The `ethereum-types` provide primitives for types that are commonly used in the
ethereum protocol. This crate is provided by [Parity](https://www.parity.io/).

Github: [ https://github.com/paritytech/primitives ](https://github.com/paritytech/primitives)


---

## Interface

### Encodable

A type is **Encodable** if it has a valid ``ssz_append`` function. This is
used to ensure that the object/type can be serialized.

```rust
pub trait Encodable {
    fn ssz_append(&self, s: &mut SszStream);
}
```


### SszStream

The main implementation is the `SszStream` struct. The struct contains a
buffer of bytes, a Vector of `uint8`.

#### new()

Create a new, empty instance of the SszStream.

```rust
let mut ssz = SszStream::new()
```

#### append<E>(&mut self, value: &E) -> &mut Self

Appends a value that can be encoded into the stream.

| Parameter | Description                              |
|:---------:|:-----------------------------------------|
| ``value`` | Encodable value to append to the stream. |

```rust
ssz.append(&x)
```

#### append_encoded_val(&mut self, vec: &Vec<u8>)

Appends some ssz encoded bytes to the stream.

| Parameter | Description                       |
|:---------:|:----------------------------------|
|  ``vec``  | A vector of serialized ssz bytes. |

```rust
let mut a = [0, 1];
ssz.append_encoded_val(&a.to_vec());
```

#### append_vec<E>(&mut self, vec: &Vec<E>)

Appends some vector (list) of encodable values to the stream.

| Parameter | Description                                   |
|:---------:|:----------------------------------------------|
|  ``vec``  | Vector of Encodable objects to be serialized. |

```rust
ssz.append_vec(attestations);
```

#### drain(self) -> Vec<u8>

Consumes the ssz stream and returns the buffer of bytes.

```rust
ssz.drain()
```



---

## Usage

### Serializing/Encoding

#### Rust

Create the `simpleserialize` stream that will produce the serialized objects.

```rust
let mut ssz = SszStream::new();
```

Encode the values that you need by using the ``append(..)`` method on the `SszStream`.

The **append** function is how the value gets serialized.

```rust
let x: u64 = 1 << 32;
ssz.append(&x);
```

To get the serialized byte vector use ``drain()`` on the `SszStream`.

```rust
ssz.drain()
```

**Example**

```rust
// 1 << 32 = 4294967296;
// As bytes it should equal: [0,0,0,1,0,0,0]
let x: u64 = 1 << 32;

// Create the new ssz stream
let mut ssz = SszStream::new();

// Serialize x
ssz.append(&x);

// Check that it is correct.
assert_eq!(ssz.drain(), vec![0,0,0,1,0,0,0]);
```
