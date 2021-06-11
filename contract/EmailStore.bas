Function InitializePrivate() Uint64
    10 STORE("owner", SIGNER())
    20 RETURN 0
End Function

Function InputStr(input String, varname String) Uint64
    10 STORE(varname, input)
    20 RETURN 0
End Function