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
loadFlatBuffer(new(flat.ScenarioCharacterNameExcelTable))

func loadFlatBuffer[T flatbuffers.FlatBuffer](table T) (T, []byte) {
  name := reflect.TypeOf(table).Elem().Name() // "ScenarioCharacterNameExcelTable"
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
then decrypt value by those:
```go
func decodeAnyScalar[T any](v T, key []byte) T {
	size := unsafe.Sizeof(v)
	if size < 4 {
		return v
	}
	switch size {
	case 4:
		if *(*uint32)(unsafe.Pointer(&v)) != 0{
			*(*uint32)(unsafe.Pointer(&v)) ^= bArrAsAnyFirst[uint32](key)
		}
	case 8:
		if *(*uint64)(unsafe.Pointer(&v)) != 0{
			*(*uint64)(unsafe.Pointer(&v)) ^= bArrAsAnyFirst[uint64](key)
		}
	default:
		b := asArray(unsafe.Pointer(&v), size)
		h := false
		for i := range b {
			if b[i] != 0 {
				h = true
				break
			}
		}
		if h {
			for i := range b {
				b[i] ^= key[i]
			}
		}
	}
	return v
}

func decodeStr(data []byte, key []byte) string {
	if len(data) == 0 {
		return `""`
	}
	raw, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		panic(err)
	}
	Xor(raw, key)
	d, _ := json.Marshal(string(utf16.Decode(bArrAsU16Arr(raw))))
	return string(d)
}
```


# copyright Yostar
