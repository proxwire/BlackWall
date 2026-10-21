Attribute VB_Name = "BlackWallInertFixture"
' Inert static-analysis fixture: the auto-open routine assigns strings only.
Private Sub AutoOpen()
    Dim Marker As String
    Dim Endpoint As String
    Dim Configuration As String
    Dim RecoveredCommand As String
    Marker = "BLACKWALL_INERT_VBA_FIXTURE"
    Endpoint = "https://" & "vba.fixture.invalid" & "/api"
    Configuration = "campaign=vba-inert"
    RecoveredCommand = Chr(112) & Chr(111) & Chr(119) & Chr(101) & Chr(114) & Chr(115) & Chr(104) & Chr(101) & Chr(108) & Chr(108) & Chr(46) & Chr(101) & Chr(120) & Chr(101) & Chr(32) & Chr(45) & Chr(78) & Chr(111) & Chr(80) & Chr(114) & Chr(111) & Chr(102) & Chr(105) & Chr(108) & Chr(101) & Chr(32) & Chr(45) & Chr(67) & Chr(111) & Chr(109) & Chr(109) & Chr(97) & Chr(110) & Chr(100) & Chr(32) & Chr(87) & Chr(114) & Chr(105) & Chr(116) & Chr(101) & Chr(45) & Chr(79) & Chr(117) & Chr(116) & Chr(112) & Chr(117) & Chr(116) & Chr(32) & Chr(66) & Chr(76) & Chr(65) & Chr(67) & Chr(75) & Chr(87) & Chr(65) & Chr(76) & Chr(76) & Chr(95) & Chr(73) & Chr(78) & Chr(69) & Chr(82) & Chr(84) & Chr(95) & Chr(86) & Chr(66) & Chr(65) & Chr(95) & Chr(67) & Chr(79) & Chr(77) & Chr(77) & Chr(65) & Chr(78) & Chr(68)
End Sub
