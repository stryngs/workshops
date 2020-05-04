Using Module .\buttons\pocBtn.psm1
Add-Type -AssemblyName PresentationFramework

## Instantiate our button class
$ourBtn = [pocBtns]::New()

## Read XAML
$xamlFile = ".\lib\gui\vsCode\poc.xaml"
$inputXML = Get-Content $xamlFile -Raw
$inputXML = $inputXML -replace 'mc:Ignorable="d"', '' -replace "x:N", 'N' -replace '^<Win.*', '<Window'
[XML]$XAML = $inputXML

#Read XAML
$reader = (New-Object System.Xml.XmlNodeReader $xaml)
try {
    $window = [Windows.Markup.XamlReader]::Load( $reader )
} catch {
    Write-Warning $_.Exception
    throw
}

# Create variables based on form control names -- named as 'var_<control name>'
$xaml.SelectNodes("//*[@Name]") | ForEach-Object {
    try {
        Set-Variable -Name "var_$($_.Name)" -Value $window.FindName($_.Name) -ErrorAction Stop
    } catch {
        throw
    }
}
## Display our variables collected from the XAML
Get-Variable var_*

## Button setups
$ourBtn.txtOutput = $var_txtOutput
$ourBtn.inpUserName = $var_inpUserName
$ourBtn.pswPassword = $var_pswPassword

## Give the click logic
$var_btnPoc.Add_Click({$ourBtn.btnPoc()})

## Dialog it
$Null = $window.ShowDialog()
