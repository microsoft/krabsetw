msbuild %~dp0..\krabs\krabs.sln /t:Rebuild /property:Configuration=DebugSigning;Platform="x64" /m:8 /nologo
msbuild %~dp0..\krabs\krabs.sln /t:Rebuild /property:Configuration=ReleaseSigning;Platform="x64" /m:8 /nologo
sn -R %~dp0..\krabs\x64\DebugSigning\O365.Security.Native.ETW.dll  %~dp0\O365.Security.pfx
sn -R %~dp0..\krabs\x64\ReleaseSigning\O365.Security.Native.ETW.dll  %~dp0\O365.Security.pfx
nuget pack  %~dp0..\O365.Security.Native.ETW.nuspec
nuget pack  %~dp0..\O365.Security.Native.ETW.Debug.nuspec
nuget pack  %~dp0..\krabsetw.nuspec