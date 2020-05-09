pragma solidity >=0.5.3 <0.7.0;

import "./EllipticCurve.sol";


/**
 * @title Secp256k1 Elliptic Curve
 * @notice Example of particularization of Elliptic Curve for secp256k1 curve
 * @author Witnet Foundation
 */
library Secp256k1 {
    uint256 private constant PP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 private constant GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
    uint256 private constant GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
    uint256 private constant AA = 0;
    uint256 private constant BB = 7;

    function scalarBaseMult(uint256 k)
        internal
        pure
        returns (uint256, uint256)
    {
        return EllipticCurve.ecMul(k, GX, GY, AA, PP);
    }

    function scalarMult(uint256 k, uint256 x, uint256 y)
        internal
        pure
        returns (uint256, uint256)
    {
        return EllipticCurve.ecMul(k, x, y, AA, PP);
    }

    function pointAdd(uint256 x1, uint256 y1, uint256 x2, uint256 y2)
        internal
        pure
        returns (uint256, uint256)
    {
        return EllipticCurve.ecAdd(x1, y1, x2, y2, AA, PP);
    }

    function eccEncrypt(
        bytes memory pubKey,
        uint256 randPrivKey,
        uint256 msgData
    ) public pure returns (bytes memory) {
        require(pubKey.length == 64, "public key length error");

        uint256 Px = Utils.bytesToUint(pubKey, 0);
        uint256 Py = Utils.bytesToUint(pubKey, 32);
        (uint256 Rx, uint256 Ry) = scalarBaseMult(randPrivKey);
        (uint256 Cx, ) = scalarMult(randPrivKey, Px, Py);
        uint256 targetX = addmod(msgData, Cx, PP);

        bytes memory tempRs = Utils.mergeBytes(
            Utils.uintToBytes(Rx),
            Utils.uintToBytes(Ry)
        );
        return Utils.mergeBytes(tempRs, Utils.uintToBytes(targetX));
    }

    function eccDecrypt(uint256 privKey, bytes memory encrypted)
        public
        pure
        returns (bytes memory)
    {
        require(encrypted.length >= 96, "encrypted data length error");

        uint256 Rx = Utils.bytesToUint(encrypted, 0);
        uint256 Ry = Utils.bytesToUint(encrypted, 32);
        uint256 targetX = Utils.bytesToUint(encrypted, 64);

        (uint256 Cx, ) = scalarMult(privKey, Rx, Ry);
        uint256 numOfMsg = addmod(targetX - Cx, PP, PP);
        return Utils.uintToBytes(numOfMsg);
    }

    function verifyRingSignature(bytes memory msgData, bytes memory sigBytes)
        public
        pure
        returns (bool valid, uint256[] memory pubsArr)
    {
        uint256[2][] memory pubs;
        uint256[] memory r;
        uint256 c0;

        (valid, pubs, r, c0) = _parseRingSignature(sigBytes);

        valid = valid && _verifyRingSignature(msgData, pubs, r, c0);
        pubsArr = Utils.nestedArrExpand(pubs);
    }

    function _parseRingSignature(bytes memory sigBytes)
        private
        pure
        returns (
            bool valid,
            uint256[2][] memory pubs,
            uint256[] memory r,
            uint256 c0
        )
    {
        if (sigBytes.length % 32 != 0) {
            return (false, pubs, r, c0);
        }

        uint256[] memory sig = Utils.bytesToUintArray(sigBytes);
        uint256 cnt = sig[0];

        if (sig.length != cnt * 3 + 2) {
            return (false, pubs, r, c0);
        }

        valid = true;
        pubs = new uint256[2][](cnt);
        r = new uint256[](cnt);
        c0 = sig[sig.length - 1];

        for (uint256 i = 0; i < cnt; i++) {
            pubs[i][0] = sig[i * 3 + 1];
            pubs[i][1] = sig[i * 3 + 2];
            r[i] = sig[i * 3 + 3];
        }
    }

    function _verifyRingSignature(
        bytes memory msgData,
        uint256[2][] memory pubs,
        uint256[] memory r,
        uint256 c0
    ) private pure returns (bool valid) {
        uint256 ciNext = c0;
        uint256 RiX = 0;
        uint256 RiY = 0;
        uint256 tempX = 0;
        uint256 tempY = 0;
        bytes32 hash;

        for (uint256 i = 0; i < pubs.length; i++) {
            (RiX, RiY) = scalarBaseMult(r[i]);
            (tempX, tempY) = scalarMult(ciNext, pubs[i][0], pubs[i][1]);
            (tempX, tempY) = pointAdd(RiX, RiY, tempX, tempY);
            hash = sha256(Utils.mergeBytes(msgData, Utils.uintToBytes(tempX)));
            ciNext = uint256(hash);
        }
        return ciNext == c0;
    }
}


library Utils {
    function pubKeyToAddr(bytes memory pubKey)
        public
        pure
        returns (address addr)
    {
        require(pubKey.length == 64, "public key length error");
        bytes32 hash = keccak256(pubKey);
        assembly {
            mstore(0, hash)
            addr := mload(0)
        }
    }

    function xyToAddr(uint256 x, uint256 y) public pure returns (address addr) {
        bytes memory pubKey = new bytes(64);
        assembly {
            mstore(add(pubKey, 32), x)
            mstore(add(pubKey, 64), y)
        }

        return pubKeyToAddr(pubKey);
    }

    function nestedArrExpand(uint256[2][] memory arr)
        internal
        pure
        returns (uint256[] memory rs)
    {
        rs = new uint256[](arr.length * 2);

        // multi-dimension array stores len in first slot, and pointers of each sub-array follows
        // so if you want to get arr[i][0] of [n][] arr, use mload(mload(arr + 32 + i * 32))
        assembly {
            let len := mload(arr)
            let _arr := add(arr, mul(add(len, 1), 32))
            let _rs := add(rs, 32)

            for {
                let end := add(_arr, mul(len, 64))
            } lt(_arr, end) {
                _arr := add(_arr, 32)
                _rs := add(_rs, 32)
            } {
                mstore(_rs, mload(_arr))
            }
        }
    }

    function mergeBytes(bytes memory b1, bytes memory b2)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory merged = new bytes(b1.length + b2.length);

        uint256 k = 0;
        for (uint256 i = 0; i < b1.length; i++) {
            merged[k] = b1[i];
            k++;
        }

        for (uint256 i = 0; i < b2.length; i++) {
            merged[k] = b2[i];
            k++;
        }
        return merged;
    }

    function uintToBytes(uint256 x) internal pure returns (bytes memory b) {
        b = new bytes(32);
        assembly {
            mstore(add(b, 32), x)
        }
    }

    function bytesToUint(bytes memory b, uint256 start)
        internal
        pure
        returns (uint256 x)
    {
        require(b.length >= start + 32, "bytes array length error");
        assembly {
            x := mload(add(b, add(32, start)))
        }
    }

    function bytesToUintArray(bytes memory input)
        internal
        pure
        returns (uint256[] memory output)
    {
        output = new uint256[](input.length / 32);
        for (uint256 i = 32; i <= input.length; i += 32) {
            assembly {
                mstore(add(output, i), mload(add(input, i)))
            }
        }
    }

    function bytesEquals(bytes memory b1, bytes memory b2)
        internal
        pure
        returns (bool)
    {
        if (b1.length != b2.length) {
            return false;
        }

        for (uint256 i = 0; i < b1.length; i++) {
            if (b1[i] != b2[i]) {
                return false;
            }
        }
        return true;
    }

    function uintToStr(uint256 i) internal pure returns (string memory) {
        if (i == 0) {
            return "0";
        }

        uint256 len = 0;
        uint256 j = i;
        while (j != 0) {
            len++;
            j /= 10;
        }

        string memory str = new string(len);
        j = len - 1;
        while (i != 0) {
            bytes(str)[j--] = bytes1(uint8(48 + (i % 10)));
            i /= 10;
        }
        return str;
    }

    function concatStr(string memory a, string memory b)
        internal
        pure
        returns (string memory)
    {
        bytes memory rs = mergeBytes(bytes(a), bytes(b));
        return string(rs);
    }
}
