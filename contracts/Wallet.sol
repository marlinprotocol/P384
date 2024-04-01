pragma solidity ^0.8.24;

import "./Curve384.sol";

contract Wallet {
    uint256 Pxhi;
    uint256 Pxlo;
    uint256 Pyhi;
    uint256 Pylo;
    constructor(uint256 _Pxhi, uint256 _Pxlo, uint256 _Pyhi, uint256 _Pylo)
        public
    {
        Pxlo = _Pxlo;
        Pxhi = _Pxhi;
        Pylo = _Pylo;
        Pyhi = _Pyhi;
    }
    
    function verifySignature(bytes32 hash, uint256 rhi, uint256 rlo, uint256 shi, uint256 slo) public view returns (bool) {
        Curve384.C384Elm memory pub = Curve384.C384Elm({
            xhi: Pxhi,
            xlo: Pxlo,
            yhi: Pyhi,
            ylo: Pylo
        });
        return Curve384.verify(pub, uint256(hash), rhi, rlo, shi, slo);
    }
}