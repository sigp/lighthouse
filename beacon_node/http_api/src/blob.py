class BlobSidecar:
    blob: List[Byte, 4096]
    proof: G1Point
    kzg_commitment: G1Point


