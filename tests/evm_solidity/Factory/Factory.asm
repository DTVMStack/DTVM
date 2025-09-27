
======= /root/DTVM/tests/evm_solidity/Factory/Factory.sol:Child =======
EVM assembly:
    /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":57:156  contract Child {... */
  mstore(0x40, 0x80)
    /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":105:154  constructor(uint256 v) {... */
  callvalue
  dup1
  iszero
  tag_1
  jumpi
  revert(0x00, 0x00)
tag_1:
  pop
  mload(0x40)
  sub(codesize, bytecodeSize)
  dup1
  bytecodeSize
  dup4
  codecopy
  dup2
  dup2
  add
  0x40
  mstore
  dup2
  add
  swap1
  tag_2
  swap2
  swap1
  tag_3
  jump	// in
tag_2:
    /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":146:147  v */
  dup1
    /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":138:143  value */
  0x00
    /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":138:147  value = v */
  dup2
  swap1
  sstore
  pop
    /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":105:154  constructor(uint256 v) {... */
  pop
    /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":57:156  contract Child {... */
  jump(tag_6)
    /* "#utility.yul":88:205   */
tag_8:
    /* "#utility.yul":197:198   */
  0x00
    /* "#utility.yul":194:195   */
  0x00
    /* "#utility.yul":187:199   */
  revert
    /* "#utility.yul":334:411   */
tag_10:
    /* "#utility.yul":371:378   */
  0x00
    /* "#utility.yul":400:405   */
  dup2
    /* "#utility.yul":389:405   */
  swap1
  pop
    /* "#utility.yul":334:411   */
  swap2
  swap1
  pop
  jump	// out
    /* "#utility.yul":417:539   */
tag_11:
    /* "#utility.yul":490:514   */
  tag_19
    /* "#utility.yul":508:513   */
  dup2
    /* "#utility.yul":490:514   */
  tag_10
  jump	// in
tag_19:
    /* "#utility.yul":483:488   */
  dup2
    /* "#utility.yul":480:515   */
  eq
    /* "#utility.yul":470:533   */
  tag_20
  jumpi
    /* "#utility.yul":529:530   */
  0x00
    /* "#utility.yul":526:527   */
  0x00
    /* "#utility.yul":519:531   */
  revert
    /* "#utility.yul":470:533   */
tag_20:
    /* "#utility.yul":417:539   */
  pop
  jump	// out
    /* "#utility.yul":545:688   */
tag_12:
    /* "#utility.yul":602:607   */
  0x00
    /* "#utility.yul":633:639   */
  dup2
    /* "#utility.yul":627:640   */
  mload
    /* "#utility.yul":618:640   */
  swap1
  pop
    /* "#utility.yul":649:682   */
  tag_22
    /* "#utility.yul":676:681   */
  dup2
    /* "#utility.yul":649:682   */
  tag_11
  jump	// in
tag_22:
    /* "#utility.yul":545:688   */
  swap3
  swap2
  pop
  pop
  jump	// out
    /* "#utility.yul":694:1045   */
tag_3:
    /* "#utility.yul":764:770   */
  0x00
    /* "#utility.yul":813:815   */
  0x20
    /* "#utility.yul":801:810   */
  dup3
    /* "#utility.yul":792:799   */
  dup5
    /* "#utility.yul":788:811   */
  sub
    /* "#utility.yul":784:816   */
  slt
    /* "#utility.yul":781:900   */
  iszero
  tag_24
  jumpi
    /* "#utility.yul":819:898   */
  tag_25
  tag_8
  jump	// in
tag_25:
    /* "#utility.yul":781:900   */
tag_24:
    /* "#utility.yul":939:940   */
  0x00
    /* "#utility.yul":964:1028   */
  tag_26
    /* "#utility.yul":1020:1027   */
  dup5
    /* "#utility.yul":1011:1017   */
  dup3
    /* "#utility.yul":1000:1009   */
  dup6
    /* "#utility.yul":996:1018   */
  add
    /* "#utility.yul":964:1028   */
  tag_12
  jump	// in
tag_26:
    /* "#utility.yul":954:1028   */
  swap2
  pop
    /* "#utility.yul":910:1038   */
  pop
    /* "#utility.yul":694:1045   */
  swap3
  swap2
  pop
  pop
  jump	// out
    /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":57:156  contract Child {... */
tag_6:
  dataSize(sub_0)
  dup1
  dataOffset(sub_0)
  0x00
  codecopy
  0x00
  return
stop

sub_0: assembly {
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":57:156  contract Child {... */
      mstore(0x40, 0x80)
      callvalue
      dup1
      iszero
      tag_1
      jumpi
      revert(0x00, 0x00)
    tag_1:
      pop
      jumpi(tag_2, lt(calldatasize, 0x04))
      shr(0xe0, calldataload(0x00))
      dup1
      0x3fa4f245
      eq
      tag_3
      jumpi
    tag_2:
      revert(0x00, 0x00)
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":78:98  uint256 public value */
    tag_3:
      tag_4
      tag_5
      jump	// in
    tag_4:
      mload(0x40)
      tag_6
      swap2
      swap1
      tag_7
      jump	// in
    tag_6:
      mload(0x40)
      dup1
      swap2
      sub
      swap1
      return
    tag_5:
      sload(0x00)
      dup2
      jump	// out
        /* "#utility.yul":7:84   */
    tag_8:
        /* "#utility.yul":44:51   */
      0x00
        /* "#utility.yul":73:78   */
      dup2
        /* "#utility.yul":62:78   */
      swap1
      pop
        /* "#utility.yul":7:84   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":90:208   */
    tag_9:
        /* "#utility.yul":177:201   */
      tag_13
        /* "#utility.yul":195:200   */
      dup2
        /* "#utility.yul":177:201   */
      tag_8
      jump	// in
    tag_13:
        /* "#utility.yul":172:175   */
      dup3
        /* "#utility.yul":165:202   */
      mstore
        /* "#utility.yul":90:208   */
      pop
      pop
      jump	// out
        /* "#utility.yul":214:436   */
    tag_7:
        /* "#utility.yul":307:311   */
      0x00
        /* "#utility.yul":345:347   */
      0x20
        /* "#utility.yul":334:343   */
      dup3
        /* "#utility.yul":330:348   */
      add
        /* "#utility.yul":322:348   */
      swap1
      pop
        /* "#utility.yul":358:429   */
      tag_15
        /* "#utility.yul":426:427   */
      0x00
        /* "#utility.yul":415:424   */
      dup4
        /* "#utility.yul":411:428   */
      add
        /* "#utility.yul":402:408   */
      dup5
        /* "#utility.yul":358:429   */
      tag_9
      jump	// in
    tag_15:
        /* "#utility.yul":214:436   */
      swap3
      swap2
      pop
      pop
      jump	// out

    auxdata: 0xa26469706673582212200a7ff00d84759c49ceda78036d1564586abe2d7e24e59a1b222d9a0412f36a8d64736f6c634300081e0033
}


======= /root/DTVM/tests/evm_solidity/Factory/Factory.sol:Factory =======
EVM assembly:
    /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":158:466  contract Factory {... */
  mstore(0x40, 0x80)
  callvalue
  dup1
  iszero
  tag_1
  jumpi
  revert(0x00, 0x00)
tag_1:
  pop
  dataSize(sub_0)
  dup1
  dataOffset(sub_0)
  0x00
  codecopy
  0x00
  return
stop

sub_0: assembly {
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":158:466  contract Factory {... */
      mstore(0x40, 0x80)
      callvalue
      dup1
      iszero
      tag_1
      jumpi
      revert(0x00, 0x00)
    tag_1:
      pop
      jumpi(tag_2, lt(calldatasize, 0x04))
      shr(0xe0, calldataload(0x00))
      dup1
      0x2fd7e73b
      eq
      tag_3
      jumpi
      dup1
      0xf9fbf886
      eq
      tag_4
      jumpi
    tag_2:
      revert(0x00, 0x00)
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":268:464  function deployChild(uint256 v) public returns (address) {... */
    tag_3:
      tag_5
      0x04
      dup1
      calldatasize
      sub
      dup2
      add
      swap1
      tag_6
      swap2
      swap1
      tag_7
      jump	// in
    tag_6:
      tag_8
      jump	// in
    tag_5:
      mload(0x40)
      tag_9
      swap2
      swap1
      tag_10
      jump	// in
    tag_9:
      mload(0x40)
      dup1
      swap2
      sub
      swap1
      return
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":181:205  address public lastChild */
    tag_4:
      tag_11
      tag_12
      jump	// in
    tag_11:
      mload(0x40)
      tag_13
      swap2
      swap1
      tag_10
      jump	// in
    tag_13:
      mload(0x40)
      dup1
      swap2
      sub
      swap1
      return
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":268:464  function deployChild(uint256 v) public returns (address) {... */
    tag_8:
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":316:323  address */
      0x00
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":335:342  Child c */
      0x00
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":355:356  v */
      dup3
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":345:357  new Child(v) */
      mload(0x40)
      tag_15
      swap1
      tag_16
      jump	// in
    tag_15:
      tag_17
      swap2
      swap1
      tag_18
      jump	// in
    tag_17:
      mload(0x40)
      dup1
      swap2
      sub
      swap1
      0x00
      create
      dup1
      iszero
      dup1
      iszero
      tag_19
      jumpi
      returndatacopy(0x00, 0x00, returndatasize)
      revert(0x00, returndatasize)
    tag_19:
      pop
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":335:357  Child c = new Child(v) */
      swap1
      pop
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":387:388  c */
      dup1
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":367:376  lastChild */
      0x00
      0x00
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":367:389  lastChild = address(c) */
      0x0100
      exp
      dup2
      sload
      dup2
      0xffffffffffffffffffffffffffffffffffffffff
      mul
      not
      and
      swap1
      dup4
      0xffffffffffffffffffffffffffffffffffffffff
      and
      mul
      or
      swap1
      sstore
      pop
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":404:431  ChildDeployed(lastChild, v) */
      0xd511261420e12ebbe5b4e2571ece315b55ca5b0d39d302c66a4ad852908eb46c
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":418:427  lastChild */
      0x00
      0x00
      swap1
      sload
      swap1
      0x0100
      exp
      swap1
      div
      0xffffffffffffffffffffffffffffffffffffffff
      and
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":429:430  v */
      dup5
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":404:431  ChildDeployed(lastChild, v) */
      mload(0x40)
      tag_20
      swap3
      swap2
      swap1
      tag_21
      jump	// in
    tag_20:
      mload(0x40)
      dup1
      swap2
      sub
      swap1
      log1
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":448:457  lastChild */
      0x00
      0x00
      swap1
      sload
      swap1
      0x0100
      exp
      swap1
      div
      0xffffffffffffffffffffffffffffffffffffffff
      and
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":441:457  return lastChild */
      swap2
      pop
      pop
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":268:464  function deployChild(uint256 v) public returns (address) {... */
      swap2
      swap1
      pop
      jump	// out
        /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":181:205  address public lastChild */
    tag_12:
      0x00
      0x00
      swap1
      sload
      swap1
      0x0100
      exp
      swap1
      div
      0xffffffffffffffffffffffffffffffffffffffff
      and
      dup2
      jump	// out
    tag_16:
      dataSize(sub_0)
      dup1
      dataOffset(sub_0)
      dup4
      codecopy
      add
      swap1
      jump	// out
        /* "#utility.yul":88:205   */
    tag_23:
        /* "#utility.yul":197:198   */
      0x00
        /* "#utility.yul":194:195   */
      0x00
        /* "#utility.yul":187:199   */
      revert
        /* "#utility.yul":334:411   */
    tag_25:
        /* "#utility.yul":371:378   */
      0x00
        /* "#utility.yul":400:405   */
      dup2
        /* "#utility.yul":389:405   */
      swap1
      pop
        /* "#utility.yul":334:411   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":417:539   */
    tag_26:
        /* "#utility.yul":490:514   */
      tag_38
        /* "#utility.yul":508:513   */
      dup2
        /* "#utility.yul":490:514   */
      tag_25
      jump	// in
    tag_38:
        /* "#utility.yul":483:488   */
      dup2
        /* "#utility.yul":480:515   */
      eq
        /* "#utility.yul":470:533   */
      tag_39
      jumpi
        /* "#utility.yul":529:530   */
      0x00
        /* "#utility.yul":526:527   */
      0x00
        /* "#utility.yul":519:531   */
      revert
        /* "#utility.yul":470:533   */
    tag_39:
        /* "#utility.yul":417:539   */
      pop
      jump	// out
        /* "#utility.yul":545:684   */
    tag_27:
        /* "#utility.yul":591:596   */
      0x00
        /* "#utility.yul":629:635   */
      dup2
        /* "#utility.yul":616:636   */
      calldataload
        /* "#utility.yul":607:636   */
      swap1
      pop
        /* "#utility.yul":645:678   */
      tag_41
        /* "#utility.yul":672:677   */
      dup2
        /* "#utility.yul":645:678   */
      tag_26
      jump	// in
    tag_41:
        /* "#utility.yul":545:684   */
      swap3
      swap2
      pop
      pop
      jump	// out
        /* "#utility.yul":690:1019   */
    tag_7:
        /* "#utility.yul":749:755   */
      0x00
        /* "#utility.yul":798:800   */
      0x20
        /* "#utility.yul":786:795   */
      dup3
        /* "#utility.yul":777:784   */
      dup5
        /* "#utility.yul":773:796   */
      sub
        /* "#utility.yul":769:801   */
      slt
        /* "#utility.yul":766:885   */
      iszero
      tag_43
      jumpi
        /* "#utility.yul":804:883   */
      tag_44
      tag_23
      jump	// in
    tag_44:
        /* "#utility.yul":766:885   */
    tag_43:
        /* "#utility.yul":924:925   */
      0x00
        /* "#utility.yul":949:1002   */
      tag_45
        /* "#utility.yul":994:1001   */
      dup5
        /* "#utility.yul":985:991   */
      dup3
        /* "#utility.yul":974:983   */
      dup6
        /* "#utility.yul":970:992   */
      add
        /* "#utility.yul":949:1002   */
      tag_27
      jump	// in
    tag_45:
        /* "#utility.yul":939:1002   */
      swap2
      pop
        /* "#utility.yul":895:1012   */
      pop
        /* "#utility.yul":690:1019   */
      swap3
      swap2
      pop
      pop
      jump	// out
        /* "#utility.yul":1025:1151   */
    tag_28:
        /* "#utility.yul":1062:1069   */
      0x00
        /* "#utility.yul":1102:1144   */
      0xffffffffffffffffffffffffffffffffffffffff
        /* "#utility.yul":1095:1100   */
      dup3
        /* "#utility.yul":1091:1145   */
      and
        /* "#utility.yul":1080:1145   */
      swap1
      pop
        /* "#utility.yul":1025:1151   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":1157:1253   */
    tag_29:
        /* "#utility.yul":1194:1201   */
      0x00
        /* "#utility.yul":1223:1247   */
      tag_48
        /* "#utility.yul":1241:1246   */
      dup3
        /* "#utility.yul":1223:1247   */
      tag_28
      jump	// in
    tag_48:
        /* "#utility.yul":1212:1247   */
      swap1
      pop
        /* "#utility.yul":1157:1253   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":1259:1377   */
    tag_30:
        /* "#utility.yul":1346:1370   */
      tag_50
        /* "#utility.yul":1364:1369   */
      dup2
        /* "#utility.yul":1346:1370   */
      tag_29
      jump	// in
    tag_50:
        /* "#utility.yul":1341:1344   */
      dup3
        /* "#utility.yul":1334:1371   */
      mstore
        /* "#utility.yul":1259:1377   */
      pop
      pop
      jump	// out
        /* "#utility.yul":1383:1605   */
    tag_10:
        /* "#utility.yul":1476:1480   */
      0x00
        /* "#utility.yul":1514:1516   */
      0x20
        /* "#utility.yul":1503:1512   */
      dup3
        /* "#utility.yul":1499:1517   */
      add
        /* "#utility.yul":1491:1517   */
      swap1
      pop
        /* "#utility.yul":1527:1598   */
      tag_52
        /* "#utility.yul":1595:1596   */
      0x00
        /* "#utility.yul":1584:1593   */
      dup4
        /* "#utility.yul":1580:1597   */
      add
        /* "#utility.yul":1571:1577   */
      dup5
        /* "#utility.yul":1527:1598   */
      tag_30
      jump	// in
    tag_52:
        /* "#utility.yul":1383:1605   */
      swap3
      swap2
      pop
      pop
      jump	// out
        /* "#utility.yul":1611:1729   */
    tag_31:
        /* "#utility.yul":1698:1722   */
      tag_54
        /* "#utility.yul":1716:1721   */
      dup2
        /* "#utility.yul":1698:1722   */
      tag_25
      jump	// in
    tag_54:
        /* "#utility.yul":1693:1696   */
      dup3
        /* "#utility.yul":1686:1723   */
      mstore
        /* "#utility.yul":1611:1729   */
      pop
      pop
      jump	// out
        /* "#utility.yul":1735:1957   */
    tag_18:
        /* "#utility.yul":1828:1832   */
      0x00
        /* "#utility.yul":1866:1868   */
      0x20
        /* "#utility.yul":1855:1864   */
      dup3
        /* "#utility.yul":1851:1869   */
      add
        /* "#utility.yul":1843:1869   */
      swap1
      pop
        /* "#utility.yul":1879:1950   */
      tag_56
        /* "#utility.yul":1947:1948   */
      0x00
        /* "#utility.yul":1936:1945   */
      dup4
        /* "#utility.yul":1932:1949   */
      add
        /* "#utility.yul":1923:1929   */
      dup5
        /* "#utility.yul":1879:1950   */
      tag_31
      jump	// in
    tag_56:
        /* "#utility.yul":1735:1957   */
      swap3
      swap2
      pop
      pop
      jump	// out
        /* "#utility.yul":1963:2295   */
    tag_21:
        /* "#utility.yul":2084:2088   */
      0x00
        /* "#utility.yul":2122:2124   */
      0x40
        /* "#utility.yul":2111:2120   */
      dup3
        /* "#utility.yul":2107:2125   */
      add
        /* "#utility.yul":2099:2125   */
      swap1
      pop
        /* "#utility.yul":2135:2206   */
      tag_58
        /* "#utility.yul":2203:2204   */
      0x00
        /* "#utility.yul":2192:2201   */
      dup4
        /* "#utility.yul":2188:2205   */
      add
        /* "#utility.yul":2179:2185   */
      dup6
        /* "#utility.yul":2135:2206   */
      tag_30
      jump	// in
    tag_58:
        /* "#utility.yul":2216:2288   */
      tag_59
        /* "#utility.yul":2284:2286   */
      0x20
        /* "#utility.yul":2273:2282   */
      dup4
        /* "#utility.yul":2269:2287   */
      add
        /* "#utility.yul":2260:2266   */
      dup5
        /* "#utility.yul":2216:2288   */
      tag_31
      jump	// in
    tag_59:
        /* "#utility.yul":1963:2295   */
      swap4
      swap3
      pop
      pop
      pop
      jump	// out
    stop

    sub_0: assembly {
            /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":57:156  contract Child {... */
          mstore(0x40, 0x80)
            /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":105:154  constructor(uint256 v) {... */
          callvalue
          dup1
          iszero
          tag_1
          jumpi
          revert(0x00, 0x00)
        tag_1:
          pop
          mload(0x40)
          sub(codesize, bytecodeSize)
          dup1
          bytecodeSize
          dup4
          codecopy
          dup2
          dup2
          add
          0x40
          mstore
          dup2
          add
          swap1
          tag_2
          swap2
          swap1
          tag_3
          jump	// in
        tag_2:
            /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":146:147  v */
          dup1
            /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":138:143  value */
          0x00
            /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":138:147  value = v */
          dup2
          swap1
          sstore
          pop
            /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":105:154  constructor(uint256 v) {... */
          pop
            /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":57:156  contract Child {... */
          jump(tag_6)
            /* "#utility.yul":88:205   */
        tag_8:
            /* "#utility.yul":197:198   */
          0x00
            /* "#utility.yul":194:195   */
          0x00
            /* "#utility.yul":187:199   */
          revert
            /* "#utility.yul":334:411   */
        tag_10:
            /* "#utility.yul":371:378   */
          0x00
            /* "#utility.yul":400:405   */
          dup2
            /* "#utility.yul":389:405   */
          swap1
          pop
            /* "#utility.yul":334:411   */
          swap2
          swap1
          pop
          jump	// out
            /* "#utility.yul":417:539   */
        tag_11:
            /* "#utility.yul":490:514   */
          tag_19
            /* "#utility.yul":508:513   */
          dup2
            /* "#utility.yul":490:514   */
          tag_10
          jump	// in
        tag_19:
            /* "#utility.yul":483:488   */
          dup2
            /* "#utility.yul":480:515   */
          eq
            /* "#utility.yul":470:533   */
          tag_20
          jumpi
            /* "#utility.yul":529:530   */
          0x00
            /* "#utility.yul":526:527   */
          0x00
            /* "#utility.yul":519:531   */
          revert
            /* "#utility.yul":470:533   */
        tag_20:
            /* "#utility.yul":417:539   */
          pop
          jump	// out
            /* "#utility.yul":545:688   */
        tag_12:
            /* "#utility.yul":602:607   */
          0x00
            /* "#utility.yul":633:639   */
          dup2
            /* "#utility.yul":627:640   */
          mload
            /* "#utility.yul":618:640   */
          swap1
          pop
            /* "#utility.yul":649:682   */
          tag_22
            /* "#utility.yul":676:681   */
          dup2
            /* "#utility.yul":649:682   */
          tag_11
          jump	// in
        tag_22:
            /* "#utility.yul":545:688   */
          swap3
          swap2
          pop
          pop
          jump	// out
            /* "#utility.yul":694:1045   */
        tag_3:
            /* "#utility.yul":764:770   */
          0x00
            /* "#utility.yul":813:815   */
          0x20
            /* "#utility.yul":801:810   */
          dup3
            /* "#utility.yul":792:799   */
          dup5
            /* "#utility.yul":788:811   */
          sub
            /* "#utility.yul":784:816   */
          slt
            /* "#utility.yul":781:900   */
          iszero
          tag_24
          jumpi
            /* "#utility.yul":819:898   */
          tag_25
          tag_8
          jump	// in
        tag_25:
            /* "#utility.yul":781:900   */
        tag_24:
            /* "#utility.yul":939:940   */
          0x00
            /* "#utility.yul":964:1028   */
          tag_26
            /* "#utility.yul":1020:1027   */
          dup5
            /* "#utility.yul":1011:1017   */
          dup3
            /* "#utility.yul":1000:1009   */
          dup6
            /* "#utility.yul":996:1018   */
          add
            /* "#utility.yul":964:1028   */
          tag_12
          jump	// in
        tag_26:
            /* "#utility.yul":954:1028   */
          swap2
          pop
            /* "#utility.yul":910:1038   */
          pop
            /* "#utility.yul":694:1045   */
          swap3
          swap2
          pop
          pop
          jump	// out
            /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":57:156  contract Child {... */
        tag_6:
          dataSize(sub_0)
          dup1
          dataOffset(sub_0)
          0x00
          codecopy
          0x00
          return
        stop

        sub_0: assembly {
                /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":57:156  contract Child {... */
              mstore(0x40, 0x80)
              callvalue
              dup1
              iszero
              tag_1
              jumpi
              revert(0x00, 0x00)
            tag_1:
              pop
              jumpi(tag_2, lt(calldatasize, 0x04))
              shr(0xe0, calldataload(0x00))
              dup1
              0x3fa4f245
              eq
              tag_3
              jumpi
            tag_2:
              revert(0x00, 0x00)
                /* "/root/DTVM/tests/evm_solidity/Factory/Factory.sol":78:98  uint256 public value */
            tag_3:
              tag_4
              tag_5
              jump	// in
            tag_4:
              mload(0x40)
              tag_6
              swap2
              swap1
              tag_7
              jump	// in
            tag_6:
              mload(0x40)
              dup1
              swap2
              sub
              swap1
              return
            tag_5:
              sload(0x00)
              dup2
              jump	// out
                /* "#utility.yul":7:84   */
            tag_8:
                /* "#utility.yul":44:51   */
              0x00
                /* "#utility.yul":73:78   */
              dup2
                /* "#utility.yul":62:78   */
              swap1
              pop
                /* "#utility.yul":7:84   */
              swap2
              swap1
              pop
              jump	// out
                /* "#utility.yul":90:208   */
            tag_9:
                /* "#utility.yul":177:201   */
              tag_13
                /* "#utility.yul":195:200   */
              dup2
                /* "#utility.yul":177:201   */
              tag_8
              jump	// in
            tag_13:
                /* "#utility.yul":172:175   */
              dup3
                /* "#utility.yul":165:202   */
              mstore
                /* "#utility.yul":90:208   */
              pop
              pop
              jump	// out
                /* "#utility.yul":214:436   */
            tag_7:
                /* "#utility.yul":307:311   */
              0x00
                /* "#utility.yul":345:347   */
              0x20
                /* "#utility.yul":334:343   */
              dup3
                /* "#utility.yul":330:348   */
              add
                /* "#utility.yul":322:348   */
              swap1
              pop
                /* "#utility.yul":358:429   */
              tag_15
                /* "#utility.yul":426:427   */
              0x00
                /* "#utility.yul":415:424   */
              dup4
                /* "#utility.yul":411:428   */
              add
                /* "#utility.yul":402:408   */
              dup5
                /* "#utility.yul":358:429   */
              tag_9
              jump	// in
            tag_15:
                /* "#utility.yul":214:436   */
              swap3
              swap2
              pop
              pop
              jump	// out

            auxdata: 0xa26469706673582212200a7ff00d84759c49ceda78036d1564586abe2d7e24e59a1b222d9a0412f36a8d64736f6c634300081e0033
        }
    }

    auxdata: 0xa26469706673582212203c31bd9a72a3d7d6c4a232f9a73cd6ce6cafbbea8d84be203c7e9a61da3c21ed64736f6c634300081e0033
}

