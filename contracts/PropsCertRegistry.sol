// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PropsCertRegistry
/// @notice Minimal on-chain registry for Props anonymous credential certificates.
///         Stores a keccak256(certificate_id) → attestation_hash mapping so that
///         certificates survive independently of the Props server.
///         No ownership, no access control, no upgradability — append-only ledger.
contract PropsCertRegistry {
    mapping(bytes32 => bytes32) private _certs;

    event CertificateStored(
        bytes32 indexed certificateId,
        bytes32 attestationHash,
        uint256 timestamp
    );

    /// @notice Store a certificate hash on-chain.
    /// @param certificateId  keccak256 of the UUID certificate_id string
    /// @param attestationHash  first 32 bytes of the Ed25519 signature hex
    function store(bytes32 certificateId, bytes32 attestationHash) external {
        _certs[certificateId] = attestationHash;
        emit CertificateStored(certificateId, attestationHash, block.timestamp);
    }

    /// @notice Look up a stored certificate hash.
    /// @param certificateId  keccak256 of the UUID certificate_id string
    /// @return attestationHash, or 0x0 if not found
    function verify(bytes32 certificateId) external view returns (bytes32) {
        return _certs[certificateId];
    }
}
