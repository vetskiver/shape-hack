// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PropsCertRegistry
/// @notice Minimal on-chain registry for Props anonymous credential certificates.
///         Stores a keccak256(certificate_id) → attestation_hash mapping so that
///         certificates survive independently of the Props server.
///         Append-only: once a certificate is stored, it cannot be overwritten or deleted.
///         Access-controlled: only the operator (deployer) or allow-listed enclave
///         addresses can store certificates. Anyone can verify (read is public).
contract PropsCertRegistry {
    address public immutable operator;
    mapping(address => bool) public allowedWriters;
    mapping(bytes32 => bytes32) private _certs;

    event CertificateStored(
        bytes32 indexed certificateId,
        bytes32 attestationHash,
        uint256 timestamp
    );
    event WriterAdded(address indexed writer);
    event WriterRemoved(address indexed writer);

    error CertificateAlreadyExists(bytes32 certificateId);
    error Unauthorized();

    modifier onlyOperator() {
        if (msg.sender != operator) revert Unauthorized();
        _;
    }

    modifier onlyAllowed() {
        if (msg.sender != operator && !allowedWriters[msg.sender]) revert Unauthorized();
        _;
    }

    constructor() {
        operator = msg.sender;
    }

    /// @notice Add an address to the allow-list (e.g. an enclave-derived wallet).
    function addWriter(address writer) external onlyOperator {
        allowedWriters[writer] = true;
        emit WriterAdded(writer);
    }

    /// @notice Remove an address from the allow-list.
    function removeWriter(address writer) external onlyOperator {
        allowedWriters[writer] = false;
        emit WriterRemoved(writer);
    }

    /// @notice Store a certificate hash on-chain. Only operator or allow-listed addresses.
    ///         Reverts if the certificate already exists (append-only).
    /// @param certificateId  keccak256 of the UUID certificate_id string
    /// @param attestationHash  SHA-256 of the signed certificate payload
    function store(bytes32 certificateId, bytes32 attestationHash) external onlyAllowed {
        if (_certs[certificateId] != bytes32(0)) {
            revert CertificateAlreadyExists(certificateId);
        }
        _certs[certificateId] = attestationHash;
        emit CertificateStored(certificateId, attestationHash, block.timestamp);
    }

    /// @notice Look up a stored certificate hash. Public — anyone can verify.
    /// @param certificateId  keccak256 of the UUID certificate_id string
    /// @return attestationHash, or 0x0 if not found
    function verify(bytes32 certificateId) external view returns (bytes32) {
        return _certs[certificateId];
    }
}
