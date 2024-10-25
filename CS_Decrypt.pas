program CS_Decrypt;

{$mode objfpc}{$H+}

uses
  SysUtils, Classes, Math, MD5, Types;

type
  TAssetStream = class(TStream)
  private
    InnerStream: TStream;
    DecryptedArray: TBytes;
    DecryptSize: Int64;
  public
    constructor Create(const Path: String);
    destructor Destroy; override;
    function Read(var Buffer; Count: Longint): Longint; override;
    function Seek(const Offset: Int64; Origin: TSeekOrigin): Int64; override;
  end;

var
  MaskList: array[0..3] of QWord;

function MD5Hash(Input: String): String;
var
  Hash: TMD5Digest;
  SB: TStringBuilder;
  I: Integer;
begin
  Hash := MD5String(Input);
  SB := TStringBuilder.Create;
  try
    for I := 0 to Length(Hash) - 1 do
      SB.Append(LowerCase(IntToHex(Hash[I], 2)));
    Result := SB.ToString;
  finally
    SB.Free;
  end;
end;

procedure Encrypt(var Buffer: TBytes; Size: Integer);
var
  I, DecSize, J: Integer;
  NowKey, V16, D: QWord;
  MaskIndex: Integer;
begin
  if (Length(Buffer) > 0) and (Size >= 1) then
  begin
    I := 0;
    while I < Size do
    begin
      NowKey := MaskList[MaskIndex];
      DecSize := Size - I;
      if DecSize > 7 then
      begin
        Move(Buffer[I], V16, 8);
        D := V16 xor NowKey;
        Move(D, Buffer[I], 8);
        DecSize := 8;
      end
      else
      begin
        for J := 0 to DecSize - 1 do
          Buffer[I + J] := Buffer[I + J] xor Byte(255 and NowKey);
      end;
      I := I + DecSize;
      MaskIndex := (MaskIndex + 1) mod Length(MaskList);
    end;
  end;
end;

procedure GetMaskList(FilePath: String);
var
  FileName, V33, V34, V35, V36, V37, V38, V39, V40, V41: String;
begin
  if FilePath <> '' then
  begin
    FileName := AnsiLowerCase(StringReplace(ExtractFileName(FilePath), ExtractFileExt(FilePath), '', []));

    V33 := MD5Hash(FileName);

    V34 := Copy(V33, 1, 16);
    V35 := Copy(V33, 17, 16);
    V36 := Copy(V33, 1, 8);
    V37 := Copy(V33, 17, 8);
    V38 := V36 + V37;
    V39 := Copy(V33, 9, 8);
    V40 := Copy(V33, 25, 8);
    V41 := V39 + V40;

    MaskList[0] := StrToQWord('$' + V34);
    MaskList[1] := StrToQWord('$' + V35);
    MaskList[2] := StrToQWord('$' + V38);
    MaskList[3] := StrToQWord('$' + V41);
  end;
end;

constructor TAssetStream.Create(const Path: String);
begin
  inherited Create;
  SetLength(DecryptedArray, 212);
  InnerStream := TFileStream.Create(Path, fmOpenRead or fmShareDenyWrite);
  DecryptSize := Min(InnerStream.Size, 212);
  InnerStream.Read(DecryptedArray[0], DecryptSize);
  GetMaskList(Path);
  Encrypt(DecryptedArray, DecryptSize);
  InnerStream.Seek(0, soBeginning);
end;

destructor TAssetStream.Destroy;
begin
  InnerStream.Free;
  inherited;
end;

function TAssetStream.Read(var Buffer; Count: Longint): Longint;
var
  Pos, DestIndex: Integer;
  ReadSize: Longint;
begin
  Pos := InnerStream.Position;
  ReadSize := InnerStream.Read(Buffer, Count);
  if DecryptSize > Pos then
  begin
    if Pos + Count > DecryptSize then
      DestIndex := DecryptSize - Pos
    else
      DestIndex := Count;
    Move(DecryptedArray[Pos], Buffer, DestIndex);
  end;
  Result := ReadSize;
end;

function TAssetStream.Seek(const Offset: Int64; Origin: TSeekOrigin): Int64;
begin
  Result := InnerStream.Seek(Offset, Origin);
end;

var
  AssetFolder: String;
  Dec: TBytes;
  Reader: TAssetStream;
  Writer: TStream;
  FileInfo: TSearchRec;
begin
  if ParamCount = 0 then
  begin
    Writeln('Counter:Side Asset Encrypter/Decrypter');
    Writeln('Usage: ' + ExtractFileName(ParamStr(0)) + ' <path-to-encrypted-or-decrypted-asset-folder>');
  end else
  begin
    AssetFolder := ParamStr(1);
    if not DirectoryExists(AssetFolder + '/output') then
      CreateDir(AssetFolder + '/output');

    if FindFirst(AssetFolder + '/*.asset', faAnyFile, FileInfo) = 0 then
    begin
      repeat
        WriteLn('Processing: ', FileInfo.Name);
        Reader := TAssetStream.Create(AssetFolder + '/' + FileInfo.Name);
        Writer := TFileStream.Create(AssetFolder + '/output/' + FileInfo.Name, fmCreate);
        try
          SetLength(Dec, Reader.Size);
          Reader.Read(Dec[0], Reader.Size);
          Writer.WriteBuffer(Dec[0], Length(Dec));
        finally
          Writer.Free;
          Reader.Free;
        end;
      until FindNext(FileInfo) <> 0;
      FindClose(FileInfo);
    end;
  end;
end.
