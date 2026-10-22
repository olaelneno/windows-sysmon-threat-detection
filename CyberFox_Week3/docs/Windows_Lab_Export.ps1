# Run in an elevated PowerShell terminal on an authorized Windows lab PC.
# Exports events as a well-formed XML document. Logs can contain sensitive data.
param([string]$OutputDir = ".\lab_exports", [int]$MaxEvents = 300)
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
function Export-EventXml([string]$LogName, [int]$EventId, [string]$OutFile) {
  $events = @(Get-WinEvent -FilterHashtable @{LogName=$LogName; Id=$EventId} -MaxEvents $MaxEvents -ErrorAction SilentlyContinue)
  $xml = New-Object System.Xml.XmlDocument
  $declaration = $xml.CreateXmlDeclaration('1.0','utf-8',$null)
  [void]$xml.AppendChild($declaration)
  $root = $xml.CreateElement('Events')
  [void]$xml.AppendChild($root)
  foreach ($item in $events) {
    $fragment = New-Object System.Xml.XmlDocument
    $fragment.LoadXml($item.ToXml())
    [void]$root.AppendChild($xml.ImportNode($fragment.DocumentElement,$true))
  }
  $xml.Save((Join-Path (Resolve-Path $OutputDir).Path $OutFile))
  Write-Host "$LogName / $EventId : $($events.Count) events exported"
}
Export-EventXml 'Security' 4625 'lab_security.xml'
Export-EventXml 'Microsoft-Windows-Sysmon/Operational' 1 'lab_sysmon.xml'
