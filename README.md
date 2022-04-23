# Moe XCOM

Just my poorly organized thoughts and code snippets on reverse engineering Blue Archive

Any help is appreciated

## Viewing/extracing Unity assets

i.e. `com.nexon.bluearchive\files\PUB\Resource\Preload\Android\*.bundle`

Use [AssetStudio](https://github.com/Perfare/AssetStudio)

## Decompiling source code

It looks like no major scripting is used there, unlike with, for example, [Azur Lane](https://github.com/Dimbreath/AzurLaneData)

All code is actually written in C# in Unity, and then compiled with IL2CPP into libil2cpp.so, so no way to extract IL or C# sources

Use [Il2CppDumper](https://github.com/Perfare/Il2CppDumper) to extract C# types and [generate script](https://github.com/djkaty/Il2CppInspector/blob/master/README.md#adding-metadata-to-your-ghidra-workflow) to use with [Ghidra SRE](https://github.com/NationalSecurityAgency/ghidra)

Read [this](https://katyscode.wordpress.com/2020/06/24/il2cpp-part-1/) and [this](https://katyscode.wordpress.com/2020/12/27/il2cpp-part-2/)

## Unpacking password-protected table bundles

Get list from files/TableBundles/TableCatalog.json

stored file name: xxHash64(zip-original-name), etc: `3622299440866786438` => `Excel.zip`

password: (Pseudocode)
```go
pass := base64.RawStdEncoding.EncodeToString(
  CreateKey(
    xxHash32.Checksum([]byte(archive.Name), 0)
    , 15)
  )
func CreateKey(key uint32, length int) []byte {
  mt := newMersenneTwister(key)
  buf := make([]byte, length)
  mt.Read(buf)
  return buf
}
```

See IDA function `TableService$$LoadBytes`

## Reading unpacked above `.bytes` files

Ref: [FlatBuffers](https://google.github.io/flatbuffers)
.fbs from il2cppDumper: [here](unpack.fbs), the generator will provided if needs
unpack steps: (partial code, issue welcome if full-code needed)
```go
func loadFlatBuffer[T flatbuffers.FlatBuffer](table T) (T, []byte) {
  name := reflect.TypeOf(table).Elem().Name()
  data, err := os.ReadFile(strings.ToLower(name) + ".bytes")
  if err != nil {
    panic(err)
  }
  _key := CreateKey(xxHash32.Checksum([]byte(name), 0), len(data))
  arr := bArrAsU64Arr(data)
  key := bArrAsU64Arr(_key)
  for i := range arr {
    arr[i] ^= key[i]
  }
  for i := len(data) - len(data)%8; i < len(data); i++ {
    data[i] ^= _key[i]
  }
  flatbuffers.GetRootAs(data, 0, table)
  return table, CreateKeyByString(strings.ReplaceAll(name, "ExcelTable", ""), 8)
}
```

# copyright Yostar