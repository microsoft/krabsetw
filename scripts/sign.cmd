msbuild krabs\krabs.sln /t:Rebuild /property:Configuration=DebugSigning;Platform="x64" /m:8 /nologo
msbuild krabs\krabs.sln /t:Rebuild /property:Configuration=ReleaseSigning;Platform="x64" /m:8 /nologo
sn -R krabs\x64\DebugSigning\O365.Security.Native.ETW.dll e:\certs\new-code-signing\O365.Security.pfx
sn -R krabs\x64\ReleaseSigning\O365.Security.Native.ETW.dll e:\certs\new-code-signing\O365.Security.pfx
nuget pack O365.Security.Native.ETW.nuspec
nuget pack O365.Security.Native.ETW.Debug.nuspec
nuget pack krabsetw.nuspec