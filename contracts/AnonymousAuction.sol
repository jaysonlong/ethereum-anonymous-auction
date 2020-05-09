pragma solidity >=0.5.3 <0.7.0;

import "./Secp256k1.sol";


contract AnonymousAuction {
    struct AuctionInfo {
        address payable auctioneer;
        bytes auctioneerPubKey;
        uint256 startingPrice;
        string desc;
    }

    struct BidderInfo {
        bytes registerInfo;
        bytes pubKey;
        bool isSet;
    }

    struct BidInfo {
        bytes32 bidHash;
        bytes bidInfo;
        bool isSet;
        bool hasReveal;
    }

    struct WinnerInfo {
        bytes12 winnerId;
        address tempAddress;
        address realAddress;
        uint160 winnerPrice;
    }

    modifier before(uint256 _time) {
        require(debug || (_time != 0 && now < _time), "not a correct time");
        _;
    }
    modifier later(uint256 _time) {
        require(debug || (_time != 0 && now >= _time), "not a correct time");
        _;
    }
    modifier onlyOwner() {
        require(msg.sender == auctionInfo.auctioneer, "not owner of contract");
        _;
    }
    modifier notEnd() {
        require(debug || isEnd == false, "auction is end");
        _;
    }
    event ReturnChargeAndDistributeDeposit(string reason);
    event DistributeDeposit(string reason);
    event IsValid(bool isValid);

    AuctionInfo public auctionInfo;
    WinnerInfo public winnerInfo;

    address payable[] public bidders;
    mapping(address => BidderInfo) public biddersInfo;
    mapping(address => bool) public tempAddresses;
    address payable[] public tAddrList;
    address[] public revaledBidders;
    mapping(address => BidInfo) public allBidInfo;
    bool private debug = true;

    //registerTime -> uploadAddrTime -> denyAddrTime -> bidTime
    // -> revealTime -> exposeTime -> denyWinnerTime -> endAuction
    uint256 private registerEndTime;
    uint256 private uploadAddrEndTime;
    uint256 private denyAddrEndTime;
    uint256 private bidEndTime;
    uint256 private revealEndTime;
    uint256 private exposeEndTime;
    uint256 private denyWinnerEndTime;

    bool public isEnd;
    string public endReason;

    uint256 private registerDuration = 60 seconds;
    uint256 private uploadAddrDuration = 60 seconds;
    uint256 private denyAddrDuration = 60 seconds;
    uint256 private bidDuration = 60 seconds;
    uint256 private revealDuration = 60 seconds;
    uint256 private exposeDuration = 60 seconds;
    uint256 private denyWinnerDuration = 60 seconds;
    uint256 private registerCharge = 1 ether;
    uint256 private auctioneerDeposit = 10 ether;

    constructor(bytes memory pubKey, uint256 startingPrice, string memory desc)
        public
        payable
    {
        require(
            msg.value == auctioneerDeposit,
            "msg.value should equal auctioneer deposit"
        );
        require(pubKey.length == 64, "public key length error");
        require(
            Utils.pubKeyToAddr(pubKey) == msg.sender,
            "public key unmatch address error"
        );

        auctionInfo = AuctionInfo(msg.sender, pubKey, startingPrice, desc);
        registerEndTime = now + registerDuration;
        uploadAddrEndTime = registerEndTime + uploadAddrDuration;
        denyAddrEndTime = uploadAddrEndTime + denyAddrDuration;
    }

    function register(bytes memory registerInfo, bytes memory pubKey)
        public
        payable
        notEnd
        before(registerEndTime)
    {
        require(
            msg.value == registerCharge,
            "msg.value should equal register charge"
        );
        require(
            msg.sender == Utils.pubKeyToAddr(pubKey),
            "public key unmatch address"
        );

        if (!biddersInfo[msg.sender].isSet) {
            bidders.push(msg.sender);
        }
        biddersInfo[msg.sender] = BidderInfo(registerInfo, pubKey, true);
    }

    function uploadTempAddr(address payable[] memory addresses)
        public
        notEnd
        onlyOwner
        later(registerEndTime)
        before(uploadAddrEndTime)
    {
        for (uint256 i = 0; i < addresses.length; i++) {
            if (!tempAddresses[addresses[i]]) {
                tAddrList.push(addresses[i]);
            }
            tempAddresses[addresses[i]] = true;
        }
    }

    function denyAddr(
        bytes12 bidderId,
        address tempAddress,
        uint256 randPrivKey
    ) public notEnd later(uploadAddrEndTime) before(denyAddrEndTime) {
        require(biddersInfo[msg.sender].isSet, "msg sender unauthorized");
        require(!tempAddresses[tempAddress], "temp address has existed");

        uint256 _bidderId = uint96(bidderId);
        uint256 origInfo = (_bidderId << 160) + uint256(tempAddress);
        bytes memory registerInfo = Secp256k1.eccEncrypt(
            auctionInfo.auctioneerPubKey,
            randPrivKey,
            origInfo
        );
        bool isValid = Utils.bytesEquals(
            registerInfo,
            biddersInfo[msg.sender].registerInfo
        );

        require(isValid, "register info unmatch");

        returnChargeAndDistributeDeposit(
            "temp addresses not correct, untrusted auctioneer"
        );
    }

    function startBidding() public notEnd onlyOwner later(denyAddrEndTime) {
        for (uint256 i = 0; i < tAddrList.length; i++) {
            tAddrList[i].transfer(registerCharge);
        }

        bidEndTime = now + bidDuration;
        revealEndTime = bidEndTime + revealDuration;
        exposeEndTime = revealEndTime + exposeDuration;
        denyWinnerEndTime = exposeEndTime + denyWinnerDuration;
    }

    function bid(bytes32 bidHash, bytes memory ringSig)
        public
        notEnd
        later(denyAddrEndTime)
        before(bidEndTime)
    {
        require(tempAddresses[msg.sender], "msg sender unauthorized");

        bytes memory _bidHash = Utils.uintToBytes(uint256(bidHash));
        (bool isValid, uint256[] memory pubs) = Secp256k1.verifyRingSignature(
            _bidHash,
            ringSig
        );
        require(isValid, "ring signature invalid");

        address addr;

        for (uint256 i = 0; i < pubs.length; i += 2) {
            addr = Utils.xyToAddr(pubs[i], pubs[i + 1]);
            require(biddersInfo[addr].isSet, "public key unauthorized");
        }

        allBidInfo[msg.sender] = BidInfo(bidHash, new bytes(0), true, false);
    }

    function reveal(bytes memory bidInfo)
        public
        notEnd
        later(bidEndTime)
        before(revealEndTime)
    {
        require(allBidInfo[msg.sender].isSet, "msg sender unauthorized");
        require(
            keccak256(bidInfo) == allBidInfo[msg.sender].bidHash,
            "bid info unmatch"
        );

        if (!allBidInfo[msg.sender].hasReveal) {
            revaledBidders.push(msg.sender);
        }
        allBidInfo[msg.sender].bidInfo = bidInfo;
        allBidInfo[msg.sender].hasReveal = true;
    }

    function exposeWinner(
        bytes12 winnerId,
        uint160 winnerPrice,
        address tempAddress
    ) public notEnd onlyOwner later(revealEndTime) before(exposeEndTime) {
        require(
            allBidInfo[tempAddress].hasReveal,
            "temp address not yet revealed"
        );

        winnerInfo.winnerPrice = winnerPrice;
        winnerInfo.winnerId = winnerId;
        winnerInfo.tempAddress = tempAddress;
    }

    function denyWinner(
        bytes12 bidderId,
        uint160 bidderPrice,
        uint256 randPrivKey
    ) public later(exposeEndTime) before(denyWinnerEndTime) {
        if (uint96(winnerInfo.winnerId) == 0) {
            distributeDeposit("winner not yet exposed, untrusted auctioneer");
        }

        require(allBidInfo[msg.sender].hasReveal, "msg sender unauthorized");

        uint256 _bidderId = uint96(bidderId);
        uint256 origInfo = (_bidderId << 160) + uint256(bidderPrice);

        bytes memory bidInfo = Secp256k1.eccEncrypt(
            auctionInfo.auctioneerPubKey,
            randPrivKey,
            origInfo
        );
        bool isValid = Utils.bytesEquals(
            bidInfo,
            allBidInfo[msg.sender].bidInfo
        );
        require(isValid, "bid info unmatch");

        if (msg.sender == winnerInfo.tempAddress) {
            require(
                bidderId != winnerInfo.winnerId ||
                    bidderPrice != winnerInfo.winnerPrice,
                "your winner info has no problem"
            );
            distributeDeposit("winner info is forged");
        } else {
            require(
                bidderPrice > winnerInfo.winnerPrice,
                "price not greater than winner"
            );
            distributeDeposit("winner price is not the highest");
        }
    }

    function endAuction() public notEnd later(denyWinnerEndTime) {
        isEnd = true;
        endReason = "auction success";
        auctionInfo.auctioneer.transfer(auctioneerDeposit);
    }

    function acceptWinning(uint256 randPrivKey)
        public
        later(exposeEndTime)
        returns (bool)
    {
        require(uint96(winnerInfo.winnerId) != 0, "winner not yet exposed");
        require(biddersInfo[msg.sender].isSet, "msg sender unauthorized");

        uint256 _winnerId = uint96(winnerInfo.winnerId);
        uint256 origInfo = (_winnerId << 160) + uint256(winnerInfo.tempAddress);

        bytes memory registerInfo = Secp256k1.eccEncrypt(
            auctionInfo.auctioneerPubKey,
            randPrivKey,
            origInfo
        );
        bool isValid = Utils.bytesEquals(
            registerInfo,
            biddersInfo[msg.sender].registerInfo
        );
        require(isValid, "info unmatch, not winner");

        winnerInfo.realAddress = msg.sender;
    }

    function returnChargeAndDistributeDeposit(string memory reason) internal {
        uint256 comfortFee = auctioneerDeposit / bidders.length;

        for (uint256 i = 0; i < bidders.length; i++) {
            bidders[i].transfer(registerCharge + comfortFee);
        }

        isEnd = true;
        endReason = reason;
        emit ReturnChargeAndDistributeDeposit(reason);
    }

    function distributeDeposit(string memory reason) internal {
        uint256 comfortFee = auctioneerDeposit / bidders.length;

        for (uint256 i = 0; i < bidders.length; i++) {
            bidders[i].transfer(comfortFee);
        }

        isEnd = true;
        endReason = reason;
        emit DistributeDeposit(reason);
    }

    function showProgress() public view notEnd returns (string memory) {
        uint256 leftBound;
        uint256 rightBound;
        uint256 currTime = now;
        string memory currStage;

        if (currTime < registerEndTime) {
            leftBound = registerEndTime - registerDuration;
            rightBound = registerEndTime;
            currStage = "register time";
        } else if (currTime < uploadAddrEndTime) {
            leftBound = registerEndTime;
            rightBound = uploadAddrEndTime;
            currStage = "upload temp addresses time";
        } else if (currTime < denyAddrEndTime) {
            leftBound = uploadAddrEndTime;
            rightBound = denyAddrEndTime;
            currStage = "deny temp addresses time";
        } else if (currTime < bidEndTime) {
            leftBound = denyAddrEndTime;
            rightBound = bidEndTime;
            currStage = "blind bid time";
        } else if (currTime < revealEndTime) {
            leftBound = bidEndTime;
            rightBound = revealEndTime;
            currStage = "reveal time";
        } else if (currTime < exposeEndTime) {
            leftBound = revealEndTime;
            rightBound = exposeEndTime;
            currStage = "expose winner time";
        } else if (currTime < denyWinnerEndTime) {
            leftBound = exposeEndTime;
            rightBound = denyWinnerEndTime;
            currStage = "deny winner time";
        } else {
            leftBound = denyWinnerEndTime;
            currStage = "auction closing time";
        }

        string memory str = Utils.concatStr("now is ", currStage);
        str = Utils.concatStr(str, ", has started for ");
        str = Utils.concatStr(str, Utils.uintToStr(currTime - leftBound));

        if (currTime < denyWinnerEndTime) {
            str = Utils.concatStr(str, " seconds, will end after ");
            str = Utils.concatStr(str, Utils.uintToStr(rightBound - currTime));
            str = Utils.concatStr(str, " seconds");
        } else {
            str = Utils.concatStr(str, " seconds");
        }

        return str;
    }

    // utils for bidder, run locally(do not submit to blockchain)
    function generateIdAndTempAddr(
        string memory randStr1,
        string memory randStr2
    ) public pure returns (bytes12, address, uint256) {
        bytes12 bidderId = bytes12(keccak256(bytes(randStr1)));
        uint256 priv = uint256(keccak256(bytes(randStr2)));
        (uint256 x, uint256 y) = Secp256k1.scalarBaseMult(priv);
        address addr = Utils.xyToAddr(x, y);

        return (bidderId, addr, priv);
    }

    // utils for bidder, run locally
    function encryptRegisterInfo(
        bytes12 bidderId,
        address tempAddress,
        string memory randomStr
    ) public view returns (bytes memory registerInfo, uint256 randPrivKey) {
        uint256 _bidderId = uint96(bidderId);
        uint256 origInfo = (_bidderId << 160) + uint256(tempAddress);

        randPrivKey = uint256(keccak256(bytes(randomStr)));
        registerInfo = Secp256k1.eccEncrypt(
            auctionInfo.auctioneerPubKey,
            randPrivKey,
            origInfo
        );
    }

    // utils for bidder, run locally
    function encryptBidInfo(
        bytes12 bidderId,
        uint160 bidderPrice,
        string memory randomStr
    )
        public
        view
        returns (bytes memory bidInfo, bytes32 hash, uint256 randPrivKey)
    {
        uint256 _bidderId = uint96(bidderId);
        uint256 origInfo = (_bidderId << 160) + uint256(bidderPrice);

        randPrivKey = uint256(keccak256(bytes(randomStr)));
        bidInfo = Secp256k1.eccEncrypt(
            auctionInfo.auctioneerPubKey,
            randPrivKey,
            origInfo
        );
        hash = keccak256(bidInfo);
    }

    // utils for auctioneer, run locally
    function decryptAllRegisterInfo(uint256 privKey)
        public
        view
        onlyOwner
        returns (bytes20[3][] memory)
    {
        bytes20[3][] memory allRegisterInfo = new bytes20[3][](bidders.length);
        bytes memory registerInfo;
        uint256 origInfo;
        bytes20 bidderId;
        bytes20 tempAddress;
        bytes20 realAddress;

        for (uint256 i = 0; i < bidders.length; i++) {
            registerInfo = biddersInfo[bidders[i]].registerInfo;
            registerInfo = Secp256k1.eccDecrypt(privKey, registerInfo);
            origInfo = Utils.bytesToUint(registerInfo, 0);

            bidderId = bytes20(uint160(origInfo >> 160));
            tempAddress = bytes20(uint160(origInfo));
            realAddress = bytes20(bidders[i]);
            allRegisterInfo[i] = [bidderId, tempAddress, realAddress];
        }

        return allRegisterInfo;
    }

    // utils for auctioneer, run locally
    function decryptAllBidInfo(uint256 privKey)
        public
        view
        onlyOwner
        returns (bytes20[4][] memory)
    {
        bytes20[4][] memory _allBidInfo = new bytes20[4][](bidders.length);
        bytes20 bidderId;
        bytes20 bidderPrice;
        bytes20 tempAddress;
        bytes20 realAddress;

        bytes memory bidInfo;
        uint256 origInfo;
        bytes memory registerInfo;
        uint256 origRegisterInfo;
        bytes20 registerBidderId;

        for (uint256 i = 0; i < revaledBidders.length; i++) {
            bidInfo = allBidInfo[revaledBidders[i]].bidInfo;
            bidInfo = Secp256k1.eccDecrypt(privKey, bidInfo);
            origInfo = Utils.bytesToUint(bidInfo, 0);

            bidderId = bytes20(uint160(origInfo >> 160));
            bidderPrice = bytes20(uint160(origInfo));
            tempAddress = bytes20(revaledBidders[i]);

            for (uint256 j = 0; j < bidders.length; j++) {
                registerInfo = biddersInfo[bidders[j]].registerInfo;
                registerInfo = Secp256k1.eccDecrypt(privKey, registerInfo);
                origRegisterInfo = Utils.bytesToUint(registerInfo, 0);
                registerBidderId = bytes20(uint160(origRegisterInfo >> 160));
                if (bidderId == registerBidderId) {
                    realAddress = bytes20(bidders[i]);
                    break;
                }
            }
            _allBidInfo[i] = [bidderId, bidderPrice, tempAddress, realAddress];
        }

        return _allBidInfo;
    }
}
