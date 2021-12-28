# Moe XCOM

Just my poorly organized thoughts and code snippets on reverse engineering Blue Archive

Any help is appreciated

## Viewing/extracing Unity assets

i.e. `com.nexon.bluearchive\files\PUB\Resource\Preload\Android\*.bundle`

Use [AssetStudio](https://github.com/Perfare/AssetStudio)

## Decompiling source code

It looks like no major scripting is used there, unlike with, for example, [Azur Lane](https://github.com/Dimbreath/AzurLaneData)

All code is actually written in C# in Unity, and then compiled with IL2CPP into libil2cpp.so, so no way to extract IL or C# sources

Use [Il2CppInspector](https://github.com/djkaty/Il2CppInspector/blob/master/README.md) to extract C# types and [generate script](https://github.com/djkaty/Il2CppInspector/blob/master/README.md#adding-metadata-to-your-ghidra-workflow) to use with [Ghidra SRE](https://github.com/NationalSecurityAgency/ghidra)

Read [this](https://katyscode.wordpress.com/2020/06/24/il2cpp-part-1/) and [this](https://katyscode.wordpress.com/2020/12/27/il2cpp-part-2/)

## Unpacking password-protected table bundles

See function `TableService_LoadBytes`

```cpp
this_00 = (ZipInputStream *)thunk_FUN_0195f408(ZipInputStream__TypeInfo);
ZipInputStream__ctor(this_00,(Stream *)baseInputStream,(MethodInfo *)0x0);
local_4c = XXHashService_CalculateHash(pSVar2,(MethodInfo *)0x0);
pSVar2 = (String *)FUN_03dfd014(&local_4c,0);
if (this_00 != (ZipInputStream *)0x0) {
  this_00->password = pSVar2;
```

Take xxHash of zip-file name, use its decimal representation as a password

## Reading unpacked above `.bytes` files

No solution here yet

See function `TableEncryptionService_XOR`

```cpp
seed = XXHashService_CalculateHash(name,(MethodInfo *)0x0);
this = (MersenneTwister *)thunk_FUN_0195f408(MersenneTwister__TypeInfo);
MersenneTwister__ctor_1(this,seed,(MethodInfo *)0x0);
if ((bytes != (Byte__Array *)0x0) && (this != (MersenneTwister *)0x0)) {
  pBVar1 = MersenneTwister_NextBytes(this,*(int32_t *)&bytes->max_length,(MethodInfo *)0x0);
  if (0 < (int)bytes->max_length) {
    uVar4 = bytes->max_length & 0xffffffff;
    uVar3 = 0;
    do {
      if (uVar4 <= uVar3) {
LAB_02ae28d4:
        uVar2 = thunk_FUN_019574bc();
                  /* WARNING: Subroutine does not return */
        FUN_019a247c(uVar2,0);
      }
      if (pBVar1 == (Byte__Array *)0x0) goto LAB_02ae28e0;
      if (*(uint *)&pBVar1->max_length <= uVar3) goto LAB_02ae28d4;
      bytes->vector[uVar3] = pBVar1->vector[uVar3] ^ bytes->vector[uVar3];
      uVar3 = uVar3 + 1;
    } while ((long)uVar3 < (long)(int)uVar4);
  }
  return bytes;
}
```

Files are also encrypted with an OTP-XOR cipher.

The key is generated with a Mersenne Twister PRNG with a password as an initial seed.

The password for each file is case sensitive name of matching C# class

For example, for file `academyfavorscheduleexceltable.bytes` the password is `AcademyFavorScheduleExcelTable`

Need to find out what to do next with decrypted file

## Find the code responsible for Korea/Elsewhere asset choices

i.e. Aris censorship

No solution here yet

Look into functions `ScenarioData_TryGetBgNameExcel`, `ScenarioData_GetBGName_GlobalExcel`
