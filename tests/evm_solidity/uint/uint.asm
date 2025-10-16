
======= tests/evm_solidity/uint/uint.sol:uintTest =======
EVM assembly:
    /* "tests/evm_solidity/uint/uint.sol":62:980  contract uintTest {... */
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
        /* "tests/evm_solidity/uint/uint.sol":62:980  contract uintTest {... */
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
      0x4f2be91f
      eq
      tag_3
      jumpi
      dup1
      0xdaf2c1cc
      eq
      tag_4
      jumpi
    tag_2:
      revert(0x00, 0x00)
        /* "tests/evm_solidity/uint/uint.sol":813:978  function add() public pure returns (uint64) {... */
    tag_3:
      tag_5
      tag_6
      jump	// in
    tag_5:
      mload(0x40)
      tag_7
      swap2
      swap1
      tag_8
      jump	// in
    tag_7:
      mload(0x40)
      dup1
      swap2
      sub
      swap1
      return
        /* "tests/evm_solidity/uint/uint.sol":83:811  function testAddOverflow() public pure returns (bool) {... */
    tag_4:
      tag_9
      tag_10
      jump	// in
    tag_9:
      mload(0x40)
      tag_11
      swap2
      swap1
      tag_12
      jump	// in
    tag_11:
      mload(0x40)
      dup1
      swap2
      sub
      swap1
      return
        /* "tests/evm_solidity/uint/uint.sol":813:978  function add() public pure returns (uint64) {... */
    tag_6:
        /* "tests/evm_solidity/uint/uint.sol":849:855  uint64 */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":861:878  uint64 uint64_max */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":881:897  type(uint64).max */
      0xffffffffffffffff
        /* "tests/evm_solidity/uint/uint.sol":861:897  uint64 uint64_max = type(uint64).max */
      swap1
      pop
        /* "tests/evm_solidity/uint/uint.sol":913:933  uint64 uint64_result */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":949:950  1 */
      0x01
        /* "tests/evm_solidity/uint/uint.sol":936:946  uint64_max */
      dup3
        /* "tests/evm_solidity/uint/uint.sol":936:950  uint64_max + 1 */
      tag_14
      swap2
      swap1
      tag_15
      jump	// in
    tag_14:
        /* "tests/evm_solidity/uint/uint.sol":913:950  uint64 uint64_result = uint64_max + 1 */
      swap1
      pop
        /* "tests/evm_solidity/uint/uint.sol":961:974  uint64_result */
      dup1
        /* "tests/evm_solidity/uint/uint.sol":954:974  return uint64_result */
      swap3
      pop
      pop
      pop
        /* "tests/evm_solidity/uint/uint.sol":813:978  function add() public pure returns (uint64) {... */
      swap1
      jump	// out
        /* "tests/evm_solidity/uint/uint.sol":83:811  function testAddOverflow() public pure returns (bool) {... */
    tag_10:
        /* "tests/evm_solidity/uint/uint.sol":131:135  bool */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":141:158  uint64 uint64_max */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":161:177  type(uint64).max */
      0xffffffffffffffff
        /* "tests/evm_solidity/uint/uint.sol":141:177  uint64 uint64_max = type(uint64).max */
      swap1
      pop
        /* "tests/evm_solidity/uint/uint.sol":193:213  uint64 uint64_result */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":229:230  1 */
      0x01
        /* "tests/evm_solidity/uint/uint.sol":216:226  uint64_max */
      dup3
        /* "tests/evm_solidity/uint/uint.sol":216:230  uint64_max + 1 */
      tag_17
      swap2
      swap1
      tag_15
      jump	// in
    tag_17:
        /* "tests/evm_solidity/uint/uint.sol":193:230  uint64 uint64_result = uint64_max + 1 */
      swap1
      pop
        /* "tests/evm_solidity/uint/uint.sol":259:260  0 */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":242:255  uint64_result */
      dup2
        /* "tests/evm_solidity/uint/uint.sol":242:260  uint64_result == 0 */
      0xffffffffffffffff
      and
      eq
        /* "tests/evm_solidity/uint/uint.sol":234:293  require(uint64_result == 0, "uint64 overflow check failed") */
      tag_18
      jumpi
      mload(0x40)
      0x08c379a000000000000000000000000000000000000000000000000000000000
      dup2
      mstore
      0x04
      add
      tag_19
      swap1
      tag_20
      jump	// in
    tag_19:
      mload(0x40)
      dup1
      swap2
      sub
      swap1
      revert
    tag_18:
        /* "tests/evm_solidity/uint/uint.sol":298:317  uint128 uint128_max */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":320:337  type(uint128).max */
      0xffffffffffffffffffffffffffffffff
        /* "tests/evm_solidity/uint/uint.sol":298:337  uint128 uint128_max = type(uint128).max */
      swap1
      pop
        /* "tests/evm_solidity/uint/uint.sol":354:376  uint128 uint128_result */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":393:394  1 */
      0x01
        /* "tests/evm_solidity/uint/uint.sol":379:390  uint128_max */
      dup3
        /* "tests/evm_solidity/uint/uint.sol":379:394  uint128_max + 1 */
      tag_21
      swap2
      swap1
      tag_22
      jump	// in
    tag_21:
        /* "tests/evm_solidity/uint/uint.sol":354:394  uint128 uint128_result = uint128_max + 1 */
      swap1
      pop
        /* "tests/evm_solidity/uint/uint.sol":424:425  0 */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":406:420  uint128_result */
      dup2
        /* "tests/evm_solidity/uint/uint.sol":406:425  uint128_result == 0 */
      0xffffffffffffffffffffffffffffffff
      and
      eq
        /* "tests/evm_solidity/uint/uint.sol":398:459  require(uint128_result == 0, "uint128 overflow check failed") */
      tag_23
      jumpi
      mload(0x40)
      0x08c379a000000000000000000000000000000000000000000000000000000000
      dup2
      mstore
      0x04
      add
      tag_24
      swap1
      tag_25
      jump	// in
    tag_24:
      mload(0x40)
      dup1
      swap2
      sub
      swap1
      revert
    tag_23:
        /* "tests/evm_solidity/uint/uint.sol":464:483  uint192 uint192_max */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":486:503  type(uint192).max */
      0xffffffffffffffffffffffffffffffffffffffffffffffff
        /* "tests/evm_solidity/uint/uint.sol":464:503  uint192 uint192_max = type(uint192).max */
      swap1
      pop
        /* "tests/evm_solidity/uint/uint.sol":520:542  uint192 uint192_result */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":559:560  1 */
      0x01
        /* "tests/evm_solidity/uint/uint.sol":545:556  uint192_max */
      dup3
        /* "tests/evm_solidity/uint/uint.sol":545:560  uint192_max + 1 */
      tag_26
      swap2
      swap1
      tag_27
      jump	// in
    tag_26:
        /* "tests/evm_solidity/uint/uint.sol":520:560  uint192 uint192_result = uint192_max + 1 */
      swap1
      pop
        /* "tests/evm_solidity/uint/uint.sol":590:591  0 */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":572:586  uint192_result */
      dup2
        /* "tests/evm_solidity/uint/uint.sol":572:591  uint192_result == 0 */
      0xffffffffffffffffffffffffffffffffffffffffffffffff
      and
      eq
        /* "tests/evm_solidity/uint/uint.sol":564:625  require(uint192_result == 0, "uint192 overflow check failed") */
      tag_28
      jumpi
      mload(0x40)
      0x08c379a000000000000000000000000000000000000000000000000000000000
      dup2
      mstore
      0x04
      add
      tag_29
      swap1
      tag_30
      jump	// in
    tag_29:
      mload(0x40)
      dup1
      swap2
      sub
      swap1
      revert
    tag_28:
        /* "tests/evm_solidity/uint/uint.sol":630:649  uint256 uint256_max */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":652:669  type(uint256).max */
      0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        /* "tests/evm_solidity/uint/uint.sol":630:669  uint256 uint256_max = type(uint256).max */
      swap1
      pop
        /* "tests/evm_solidity/uint/uint.sol":686:708  uint256 uint256_result */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":725:726  1 */
      0x01
        /* "tests/evm_solidity/uint/uint.sol":711:722  uint256_max */
      dup3
        /* "tests/evm_solidity/uint/uint.sol":711:726  uint256_max + 1 */
      tag_31
      swap2
      swap1
      tag_32
      jump	// in
    tag_31:
        /* "tests/evm_solidity/uint/uint.sol":686:726  uint256 uint256_result = uint256_max + 1 */
      swap1
      pop
        /* "tests/evm_solidity/uint/uint.sol":756:757  0 */
      0x00
        /* "tests/evm_solidity/uint/uint.sol":738:752  uint256_result */
      dup2
        /* "tests/evm_solidity/uint/uint.sol":738:757  uint256_result == 0 */
      eq
        /* "tests/evm_solidity/uint/uint.sol":730:791  require(uint256_result == 0, "uint256 overflow check failed") */
      tag_33
      jumpi
      mload(0x40)
      0x08c379a000000000000000000000000000000000000000000000000000000000
      dup2
      mstore
      0x04
      add
      tag_34
      swap1
      tag_35
      jump	// in
    tag_34:
      mload(0x40)
      dup1
      swap2
      sub
      swap1
      revert
    tag_33:
        /* "tests/evm_solidity/uint/uint.sol":803:807  true */
      0x01
        /* "tests/evm_solidity/uint/uint.sol":796:807  return true */
      swap9
      pop
      pop
      pop
      pop
      pop
      pop
      pop
      pop
      pop
        /* "tests/evm_solidity/uint/uint.sol":83:811  function testAddOverflow() public pure returns (bool) {... */
      swap1
      jump	// out
        /* "#utility.yul":7:108   */
    tag_36:
        /* "#utility.yul":43:50   */
      0x00
        /* "#utility.yul":83:101   */
      0xffffffffffffffff
        /* "#utility.yul":76:81   */
      dup3
        /* "#utility.yul":72:102   */
      and
        /* "#utility.yul":61:102   */
      swap1
      pop
        /* "#utility.yul":7:108   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":114:229   */
    tag_37:
        /* "#utility.yul":199:222   */
      tag_56
        /* "#utility.yul":216:221   */
      dup2
        /* "#utility.yul":199:222   */
      tag_36
      jump	// in
    tag_56:
        /* "#utility.yul":194:197   */
      dup3
        /* "#utility.yul":187:223   */
      mstore
        /* "#utility.yul":114:229   */
      pop
      pop
      jump	// out
        /* "#utility.yul":235:453   */
    tag_8:
        /* "#utility.yul":326:330   */
      0x00
        /* "#utility.yul":364:366   */
      0x20
        /* "#utility.yul":353:362   */
      dup3
        /* "#utility.yul":349:367   */
      add
        /* "#utility.yul":341:367   */
      swap1
      pop
        /* "#utility.yul":377:446   */
      tag_58
        /* "#utility.yul":443:444   */
      0x00
        /* "#utility.yul":432:441   */
      dup4
        /* "#utility.yul":428:445   */
      add
        /* "#utility.yul":419:425   */
      dup5
        /* "#utility.yul":377:446   */
      tag_37
      jump	// in
    tag_58:
        /* "#utility.yul":235:453   */
      swap3
      swap2
      pop
      pop
      jump	// out
        /* "#utility.yul":459:549   */
    tag_38:
        /* "#utility.yul":493:500   */
      0x00
        /* "#utility.yul":536:541   */
      dup2
        /* "#utility.yul":529:542   */
      iszero
        /* "#utility.yul":522:543   */
      iszero
        /* "#utility.yul":511:543   */
      swap1
      pop
        /* "#utility.yul":459:549   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":555:664   */
    tag_39:
        /* "#utility.yul":636:657   */
      tag_61
        /* "#utility.yul":651:656   */
      dup2
        /* "#utility.yul":636:657   */
      tag_38
      jump	// in
    tag_61:
        /* "#utility.yul":631:634   */
      dup3
        /* "#utility.yul":624:658   */
      mstore
        /* "#utility.yul":555:664   */
      pop
      pop
      jump	// out
        /* "#utility.yul":670:880   */
    tag_12:
        /* "#utility.yul":757:761   */
      0x00
        /* "#utility.yul":795:797   */
      0x20
        /* "#utility.yul":784:793   */
      dup3
        /* "#utility.yul":780:798   */
      add
        /* "#utility.yul":772:798   */
      swap1
      pop
        /* "#utility.yul":808:873   */
      tag_63
        /* "#utility.yul":870:871   */
      0x00
        /* "#utility.yul":859:868   */
      dup4
        /* "#utility.yul":855:872   */
      add
        /* "#utility.yul":846:852   */
      dup5
        /* "#utility.yul":808:873   */
      tag_39
      jump	// in
    tag_63:
        /* "#utility.yul":670:880   */
      swap3
      swap2
      pop
      pop
      jump	// out
        /* "#utility.yul":886:1066   */
    tag_40:
        /* "#utility.yul":934:1011   */
      0x4e487b7100000000000000000000000000000000000000000000000000000000
        /* "#utility.yul":931:932   */
      0x00
        /* "#utility.yul":924:1012   */
      mstore
        /* "#utility.yul":1031:1035   */
      0x11
        /* "#utility.yul":1028:1029   */
      0x04
        /* "#utility.yul":1021:1036   */
      mstore
        /* "#utility.yul":1055:1059   */
      0x24
        /* "#utility.yul":1052:1053   */
      0x00
        /* "#utility.yul":1045:1060   */
      revert
        /* "#utility.yul":1072:1277   */
    tag_15:
        /* "#utility.yul":1111:1114   */
      0x00
        /* "#utility.yul":1130:1149   */
      tag_66
        /* "#utility.yul":1147:1148   */
      dup3
        /* "#utility.yul":1130:1149   */
      tag_36
      jump	// in
    tag_66:
        /* "#utility.yul":1125:1149   */
      swap2
      pop
        /* "#utility.yul":1163:1182   */
      tag_67
        /* "#utility.yul":1180:1181   */
      dup4
        /* "#utility.yul":1163:1182   */
      tag_36
      jump	// in
    tag_67:
        /* "#utility.yul":1158:1182   */
      swap3
      pop
        /* "#utility.yul":1205:1206   */
      dup3
        /* "#utility.yul":1202:1203   */
      dup3
        /* "#utility.yul":1198:1207   */
      add
        /* "#utility.yul":1191:1207   */
      swap1
      pop
        /* "#utility.yul":1228:1246   */
      0xffffffffffffffff
        /* "#utility.yul":1223:1226   */
      dup2
        /* "#utility.yul":1220:1247   */
      gt
        /* "#utility.yul":1217:1270   */
      iszero
      tag_68
      jumpi
        /* "#utility.yul":1250:1268   */
      tag_69
      tag_40
      jump	// in
    tag_69:
        /* "#utility.yul":1217:1270   */
    tag_68:
        /* "#utility.yul":1072:1277   */
      swap3
      swap2
      pop
      pop
      jump	// out
        /* "#utility.yul":1283:1452   */
    tag_41:
        /* "#utility.yul":1367:1378   */
      0x00
        /* "#utility.yul":1401:1407   */
      dup3
        /* "#utility.yul":1396:1399   */
      dup3
        /* "#utility.yul":1389:1408   */
      mstore
        /* "#utility.yul":1441:1445   */
      0x20
        /* "#utility.yul":1436:1439   */
      dup3
        /* "#utility.yul":1432:1446   */
      add
        /* "#utility.yul":1417:1446   */
      swap1
      pop
        /* "#utility.yul":1283:1452   */
      swap3
      swap2
      pop
      pop
      jump	// out
        /* "#utility.yul":1458:1636   */
    tag_42:
        /* "#utility.yul":1598:1628   */
      0x75696e743634206f766572666c6f7720636865636b206661696c656400000000
        /* "#utility.yul":1594:1595   */
      0x00
        /* "#utility.yul":1586:1592   */
      dup3
        /* "#utility.yul":1582:1596   */
      add
        /* "#utility.yul":1575:1629   */
      mstore
        /* "#utility.yul":1458:1636   */
      pop
      jump	// out
        /* "#utility.yul":1642:2008   */
    tag_43:
        /* "#utility.yul":1784:1787   */
      0x00
        /* "#utility.yul":1805:1872   */
      tag_73
        /* "#utility.yul":1869:1871   */
      0x1c
        /* "#utility.yul":1864:1867   */
      dup4
        /* "#utility.yul":1805:1872   */
      tag_41
      jump	// in
    tag_73:
        /* "#utility.yul":1798:1872   */
      swap2
      pop
        /* "#utility.yul":1881:1974   */
      tag_74
        /* "#utility.yul":1970:1973   */
      dup3
        /* "#utility.yul":1881:1974   */
      tag_42
      jump	// in
    tag_74:
        /* "#utility.yul":1999:2001   */
      0x20
        /* "#utility.yul":1994:1997   */
      dup3
        /* "#utility.yul":1990:2002   */
      add
        /* "#utility.yul":1983:2002   */
      swap1
      pop
        /* "#utility.yul":1642:2008   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":2014:2433   */
    tag_20:
        /* "#utility.yul":2180:2184   */
      0x00
        /* "#utility.yul":2218:2220   */
      0x20
        /* "#utility.yul":2207:2216   */
      dup3
        /* "#utility.yul":2203:2221   */
      add
        /* "#utility.yul":2195:2221   */
      swap1
      pop
        /* "#utility.yul":2267:2276   */
      dup2
        /* "#utility.yul":2261:2265   */
      dup2
        /* "#utility.yul":2257:2277   */
      sub
        /* "#utility.yul":2253:2254   */
      0x00
        /* "#utility.yul":2242:2251   */
      dup4
        /* "#utility.yul":2238:2255   */
      add
        /* "#utility.yul":2231:2278   */
      mstore
        /* "#utility.yul":2295:2426   */
      tag_76
        /* "#utility.yul":2421:2425   */
      dup2
        /* "#utility.yul":2295:2426   */
      tag_43
      jump	// in
    tag_76:
        /* "#utility.yul":2287:2426   */
      swap1
      pop
        /* "#utility.yul":2014:2433   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":2439:2557   */
    tag_44:
        /* "#utility.yul":2476:2483   */
      0x00
        /* "#utility.yul":2516:2550   */
      0xffffffffffffffffffffffffffffffff
        /* "#utility.yul":2509:2514   */
      dup3
        /* "#utility.yul":2505:2551   */
      and
        /* "#utility.yul":2494:2551   */
      swap1
      pop
        /* "#utility.yul":2439:2557   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":2563:2787   */
    tag_22:
        /* "#utility.yul":2603:2606   */
      0x00
        /* "#utility.yul":2622:2642   */
      tag_79
        /* "#utility.yul":2640:2641   */
      dup3
        /* "#utility.yul":2622:2642   */
      tag_44
      jump	// in
    tag_79:
        /* "#utility.yul":2617:2642   */
      swap2
      pop
        /* "#utility.yul":2656:2676   */
      tag_80
        /* "#utility.yul":2674:2675   */
      dup4
        /* "#utility.yul":2656:2676   */
      tag_44
      jump	// in
    tag_80:
        /* "#utility.yul":2651:2676   */
      swap3
      pop
        /* "#utility.yul":2699:2700   */
      dup3
        /* "#utility.yul":2696:2697   */
      dup3
        /* "#utility.yul":2692:2701   */
      add
        /* "#utility.yul":2685:2701   */
      swap1
      pop
        /* "#utility.yul":2722:2756   */
      0xffffffffffffffffffffffffffffffff
        /* "#utility.yul":2717:2720   */
      dup2
        /* "#utility.yul":2714:2757   */
      gt
        /* "#utility.yul":2711:2780   */
      iszero
      tag_81
      jumpi
        /* "#utility.yul":2760:2778   */
      tag_82
      tag_40
      jump	// in
    tag_82:
        /* "#utility.yul":2711:2780   */
    tag_81:
        /* "#utility.yul":2563:2787   */
      swap3
      swap2
      pop
      pop
      jump	// out
        /* "#utility.yul":2793:2972   */
    tag_45:
        /* "#utility.yul":2933:2964   */
      0x75696e74313238206f766572666c6f7720636865636b206661696c6564000000
        /* "#utility.yul":2929:2930   */
      0x00
        /* "#utility.yul":2921:2927   */
      dup3
        /* "#utility.yul":2917:2931   */
      add
        /* "#utility.yul":2910:2965   */
      mstore
        /* "#utility.yul":2793:2972   */
      pop
      jump	// out
        /* "#utility.yul":2978:3344   */
    tag_46:
        /* "#utility.yul":3120:3123   */
      0x00
        /* "#utility.yul":3141:3208   */
      tag_85
        /* "#utility.yul":3205:3207   */
      0x1d
        /* "#utility.yul":3200:3203   */
      dup4
        /* "#utility.yul":3141:3208   */
      tag_41
      jump	// in
    tag_85:
        /* "#utility.yul":3134:3208   */
      swap2
      pop
        /* "#utility.yul":3217:3310   */
      tag_86
        /* "#utility.yul":3306:3309   */
      dup3
        /* "#utility.yul":3217:3310   */
      tag_45
      jump	// in
    tag_86:
        /* "#utility.yul":3335:3337   */
      0x20
        /* "#utility.yul":3330:3333   */
      dup3
        /* "#utility.yul":3326:3338   */
      add
        /* "#utility.yul":3319:3338   */
      swap1
      pop
        /* "#utility.yul":2978:3344   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":3350:3769   */
    tag_25:
        /* "#utility.yul":3516:3520   */
      0x00
        /* "#utility.yul":3554:3556   */
      0x20
        /* "#utility.yul":3543:3552   */
      dup3
        /* "#utility.yul":3539:3557   */
      add
        /* "#utility.yul":3531:3557   */
      swap1
      pop
        /* "#utility.yul":3603:3612   */
      dup2
        /* "#utility.yul":3597:3601   */
      dup2
        /* "#utility.yul":3593:3613   */
      sub
        /* "#utility.yul":3589:3590   */
      0x00
        /* "#utility.yul":3578:3587   */
      dup4
        /* "#utility.yul":3574:3591   */
      add
        /* "#utility.yul":3567:3614   */
      mstore
        /* "#utility.yul":3631:3762   */
      tag_88
        /* "#utility.yul":3757:3761   */
      dup2
        /* "#utility.yul":3631:3762   */
      tag_46
      jump	// in
    tag_88:
        /* "#utility.yul":3623:3762   */
      swap1
      pop
        /* "#utility.yul":3350:3769   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":3775:3909   */
    tag_47:
        /* "#utility.yul":3812:3819   */
      0x00
        /* "#utility.yul":3852:3902   */
      0xffffffffffffffffffffffffffffffffffffffffffffffff
        /* "#utility.yul":3845:3850   */
      dup3
        /* "#utility.yul":3841:3903   */
      and
        /* "#utility.yul":3830:3903   */
      swap1
      pop
        /* "#utility.yul":3775:3909   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":3915:4155   */
    tag_27:
        /* "#utility.yul":3955:3958   */
      0x00
        /* "#utility.yul":3974:3994   */
      tag_91
        /* "#utility.yul":3992:3993   */
      dup3
        /* "#utility.yul":3974:3994   */
      tag_47
      jump	// in
    tag_91:
        /* "#utility.yul":3969:3994   */
      swap2
      pop
        /* "#utility.yul":4008:4028   */
      tag_92
        /* "#utility.yul":4026:4027   */
      dup4
        /* "#utility.yul":4008:4028   */
      tag_47
      jump	// in
    tag_92:
        /* "#utility.yul":4003:4028   */
      swap3
      pop
        /* "#utility.yul":4051:4052   */
      dup3
        /* "#utility.yul":4048:4049   */
      dup3
        /* "#utility.yul":4044:4053   */
      add
        /* "#utility.yul":4037:4053   */
      swap1
      pop
        /* "#utility.yul":4074:4124   */
      0xffffffffffffffffffffffffffffffffffffffffffffffff
        /* "#utility.yul":4069:4072   */
      dup2
        /* "#utility.yul":4066:4125   */
      gt
        /* "#utility.yul":4063:4148   */
      iszero
      tag_93
      jumpi
        /* "#utility.yul":4128:4146   */
      tag_94
      tag_40
      jump	// in
    tag_94:
        /* "#utility.yul":4063:4148   */
    tag_93:
        /* "#utility.yul":3915:4155   */
      swap3
      swap2
      pop
      pop
      jump	// out
        /* "#utility.yul":4161:4340   */
    tag_48:
        /* "#utility.yul":4301:4332   */
      0x75696e74313932206f766572666c6f7720636865636b206661696c6564000000
        /* "#utility.yul":4297:4298   */
      0x00
        /* "#utility.yul":4289:4295   */
      dup3
        /* "#utility.yul":4285:4299   */
      add
        /* "#utility.yul":4278:4333   */
      mstore
        /* "#utility.yul":4161:4340   */
      pop
      jump	// out
        /* "#utility.yul":4346:4712   */
    tag_49:
        /* "#utility.yul":4488:4491   */
      0x00
        /* "#utility.yul":4509:4576   */
      tag_97
        /* "#utility.yul":4573:4575   */
      0x1d
        /* "#utility.yul":4568:4571   */
      dup4
        /* "#utility.yul":4509:4576   */
      tag_41
      jump	// in
    tag_97:
        /* "#utility.yul":4502:4576   */
      swap2
      pop
        /* "#utility.yul":4585:4678   */
      tag_98
        /* "#utility.yul":4674:4677   */
      dup3
        /* "#utility.yul":4585:4678   */
      tag_48
      jump	// in
    tag_98:
        /* "#utility.yul":4703:4705   */
      0x20
        /* "#utility.yul":4698:4701   */
      dup3
        /* "#utility.yul":4694:4706   */
      add
        /* "#utility.yul":4687:4706   */
      swap1
      pop
        /* "#utility.yul":4346:4712   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":4718:5137   */
    tag_30:
        /* "#utility.yul":4884:4888   */
      0x00
        /* "#utility.yul":4922:4924   */
      0x20
        /* "#utility.yul":4911:4920   */
      dup3
        /* "#utility.yul":4907:4925   */
      add
        /* "#utility.yul":4899:4925   */
      swap1
      pop
        /* "#utility.yul":4971:4980   */
      dup2
        /* "#utility.yul":4965:4969   */
      dup2
        /* "#utility.yul":4961:4981   */
      sub
        /* "#utility.yul":4957:4958   */
      0x00
        /* "#utility.yul":4946:4955   */
      dup4
        /* "#utility.yul":4942:4959   */
      add
        /* "#utility.yul":4935:4982   */
      mstore
        /* "#utility.yul":4999:5130   */
      tag_100
        /* "#utility.yul":5125:5129   */
      dup2
        /* "#utility.yul":4999:5130   */
      tag_49
      jump	// in
    tag_100:
        /* "#utility.yul":4991:5130   */
      swap1
      pop
        /* "#utility.yul":4718:5137   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":5143:5220   */
    tag_50:
        /* "#utility.yul":5180:5187   */
      0x00
        /* "#utility.yul":5209:5214   */
      dup2
        /* "#utility.yul":5198:5214   */
      swap1
      pop
        /* "#utility.yul":5143:5220   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":5226:5417   */
    tag_32:
        /* "#utility.yul":5266:5269   */
      0x00
        /* "#utility.yul":5285:5305   */
      tag_103
        /* "#utility.yul":5303:5304   */
      dup3
        /* "#utility.yul":5285:5305   */
      tag_50
      jump	// in
    tag_103:
        /* "#utility.yul":5280:5305   */
      swap2
      pop
        /* "#utility.yul":5319:5339   */
      tag_104
        /* "#utility.yul":5337:5338   */
      dup4
        /* "#utility.yul":5319:5339   */
      tag_50
      jump	// in
    tag_104:
        /* "#utility.yul":5314:5339   */
      swap3
      pop
        /* "#utility.yul":5362:5363   */
      dup3
        /* "#utility.yul":5359:5360   */
      dup3
        /* "#utility.yul":5355:5364   */
      add
        /* "#utility.yul":5348:5364   */
      swap1
      pop
        /* "#utility.yul":5383:5386   */
      dup1
        /* "#utility.yul":5380:5381   */
      dup3
        /* "#utility.yul":5377:5387   */
      gt
        /* "#utility.yul":5374:5410   */
      iszero
      tag_105
      jumpi
        /* "#utility.yul":5390:5408   */
      tag_106
      tag_40
      jump	// in
    tag_106:
        /* "#utility.yul":5374:5410   */
    tag_105:
        /* "#utility.yul":5226:5417   */
      swap3
      swap2
      pop
      pop
      jump	// out
        /* "#utility.yul":5423:5602   */
    tag_51:
        /* "#utility.yul":5563:5594   */
      0x75696e74323536206f766572666c6f7720636865636b206661696c6564000000
        /* "#utility.yul":5559:5560   */
      0x00
        /* "#utility.yul":5551:5557   */
      dup3
        /* "#utility.yul":5547:5561   */
      add
        /* "#utility.yul":5540:5595   */
      mstore
        /* "#utility.yul":5423:5602   */
      pop
      jump	// out
        /* "#utility.yul":5608:5974   */
    tag_52:
        /* "#utility.yul":5750:5753   */
      0x00
        /* "#utility.yul":5771:5838   */
      tag_109
        /* "#utility.yul":5835:5837   */
      0x1d
        /* "#utility.yul":5830:5833   */
      dup4
        /* "#utility.yul":5771:5838   */
      tag_41
      jump	// in
    tag_109:
        /* "#utility.yul":5764:5838   */
      swap2
      pop
        /* "#utility.yul":5847:5940   */
      tag_110
        /* "#utility.yul":5936:5939   */
      dup3
        /* "#utility.yul":5847:5940   */
      tag_51
      jump	// in
    tag_110:
        /* "#utility.yul":5965:5967   */
      0x20
        /* "#utility.yul":5960:5963   */
      dup3
        /* "#utility.yul":5956:5968   */
      add
        /* "#utility.yul":5949:5968   */
      swap1
      pop
        /* "#utility.yul":5608:5974   */
      swap2
      swap1
      pop
      jump	// out
        /* "#utility.yul":5980:6399   */
    tag_35:
        /* "#utility.yul":6146:6150   */
      0x00
        /* "#utility.yul":6184:6186   */
      0x20
        /* "#utility.yul":6173:6182   */
      dup3
        /* "#utility.yul":6169:6187   */
      add
        /* "#utility.yul":6161:6187   */
      swap1
      pop
        /* "#utility.yul":6233:6242   */
      dup2
        /* "#utility.yul":6227:6231   */
      dup2
        /* "#utility.yul":6223:6243   */
      sub
        /* "#utility.yul":6219:6220   */
      0x00
        /* "#utility.yul":6208:6217   */
      dup4
        /* "#utility.yul":6204:6221   */
      add
        /* "#utility.yul":6197:6244   */
      mstore
        /* "#utility.yul":6261:6392   */
      tag_112
        /* "#utility.yul":6387:6391   */
      dup2
        /* "#utility.yul":6261:6392   */
      tag_52
      jump	// in
    tag_112:
        /* "#utility.yul":6253:6392   */
      swap1
      pop
        /* "#utility.yul":5980:6399   */
      swap2
      swap1
      pop
      jump	// out

    auxdata: 0xa26469706673582212203178c4255b3fe2c9f62c06b6e85c8713cab8c789b2d36c2a5c794664eb0af43264736f6c634300081e0033
}

