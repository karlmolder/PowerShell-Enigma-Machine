#Enigma Encoder - www.101computing.net/enigma-encoder/
#converted from Python to PowerShell - Karl Molder 2022

# ----------------- Enigma Settings -----------------
$rotors = @("I","II","III")
$reflector = "UKW-B"
$ringSettings = "ABC"
$ringPositions = "DEF" 
$plugboard = "AT BS DE FM IR KN LZ OW PV XY"
# ---------------------------------------------------

function caesarShift {
  [cmdletbinding()]
  Param (
    [string]$str,
    [string]$amount
  )
  $output = ""
  
  for($i = 0; $i -lt $str.length; $i++) {
    $c = $str[$i]
    $code = [byte][char]$c
    if (($code -ge 65) -and ($code -le 90)){
      $c = [char]((($code - 65 + $amount) % 26) + 65)
      $output = $output + $c
    }
  }

  return $output
}

function encode {
  [cmdletbinding()]
  Param (
    [string]$plaintext
  )

  $rotor1 = "EKMFLGDQVZNTOWYHXUSPAIBRCJ"
  $rotor1Notch = "Q"
  $rotor2 = "AJDKSIRUXBLHWTMCQGZNPYFVOE"
  $rotor2Notch = "E"
  $rotor3 = "BDFHJLCPRTXVZNYEIWGAKMUSQO"
  $rotor3Notch = "V"
  $rotor4 = "ESOVPZJAYQUIRHXLNFTGKDCMWB"
  $rotor4Notch = "J"
  $rotor5 = "VZBRGITYUPSDNHLXAWMJQOFECK"
  $rotor5Notch = "Z" 
  
  $rotorDict = @{"I"=$rotor1;"II"=$rotor2;"III"=$rotor3;"IV"=$rotor4;"V"= $rotor5}
  $rotorNotchDict = @{"I"=$rotor1Notch;"II"=$rotor2Notch;"III"=$rotor3Notch;"IV"=$rotor4Notch;"V"=$rotor5Notch}  
  
  $reflectorB = @{"A"="Y";"Y"="A";"B"="R";"R"="B";"C"="U";"U"="C";"D"="H";"H"="D";"E"="Q";"Q"="E";"F"="S";"S"="F";"G"="L";"L"="G";"I"="P";"P"="I";"J"="X";"X"="J";"K"="N";"N"="K";"M"="O";"O"="M";"T"="Z";"Z"="T";"V"="W";"W"="V"}
  $reflectorC = @{"A"="F";"F"="A";"B"="V";"V"="B";"C"="P";"P"="C";"D"="J";"J"="D";"E"="I";"I"="E";"G"="O";"O"="G";"H"="Y";"Y"="H";"K"="R";"R"="K";"L"="Z";"Z"="L";"M"="X";"X"="M";"N"="W";"W"="N";"Q"="T";"T"="Q";"S"="U";"U"="S"}
  
  $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  
  if ($reflector -eq "UKW-B") {
    $reflectorDict = $reflectorB
  } else {
    $reflectorDict = $reflectorC
  }
  
  #A = Left,  B = Mid,  C=Right 
  $rotorA = $rotorDict[$rotors[0]]
  $rotorB = $rotorDict[$rotors[1]]
  $rotorC = $rotorDict[$rotors[2]]
  $rotorBNotch = $rotorNotchDict[$rotors[1]]
  $rotorCNotch = $rotorNotchDict[$rotors[2]]
  
  [string]$rotorALetter = $ringPositions[0]
  [string]$rotorBLetter = $ringPositions[1]
  [string]$rotorCLetter = $ringPositions[2]
  
  [string]$rotorASetting = $ringSettings[0]
  $offsetASetting = $alphabet.IndexOf($rotorASetting)
  [string]$rotorBSetting = $ringSettings[1]
  $offsetBSetting = $alphabet.IndexOf($rotorBSetting)
  [string]$rotorCSetting = $ringSettings[2]
  $offsetCSetting = $alphabet.IndexOf($rotorCSetting)
  
  $rotorA = caesarShift $rotorA $offsetASetting
  $rotorB = caesarShift $rotorB $offsetBSetting
  $rotorC = caesarShift $rotorC $offsetCSetting
  
  if ($offsetASetting -gt 0) {
    $i = 1-$offsetASetting; $j = -$offsetASetting-1
    $rotorA = ($rotorA[26-$offsetASetting] + $rotorA[$i..($rotorA.Length+$j)]) -replace " ",""
  }
  if ($offsetBSetting -gt 0) {
    $i = 1-$offsetBSetting; $j = -$offsetBSetting-1
    $rotorB = ($rotorB[26-$offsetBSetting] + $rotorB[$i..($rotorB.Length+$j)]) -replace " ",""
  }
  if ($offsetCSetting -gt 0) {
    $i = 1-$offsetCSetting; $j = -$offsetCSetting-1
    $rotorC = ($rotorC[26-$offsetCSetting] + $rotorC[$i..($rotorC.Length+$j)]) -replace " ",""
  }

  $ciphertext = ""
  
  #Converplugboard settings into a Dictionary (hashtable)
  $plugboardConnections = $plugboard.ToUpper().split(" ")
  $plugboardDict = @{}
  foreach ($pair in $plugboardConnections) {
    if ($pair.length -eq 2) {
      $plugboardDict.Add([string]$pair[0],[string]$pair[1])
      $plugboardDict.Add([string]$pair[1],[string]$pair[0])
    } 
  }
  
  $plaintext = $plaintext.ToUpper()  
  foreach ($letter in $plaintext.toCharArray()) {
    $letter = $letter.ToString()
    $encryptedLetter = $letter  
    
    if ($alphabet.contains($letter)) {
      #Rotate Rotors - This happens as soon as a key is pressed, before encrypting the letter!
      $rotorTrigger = $False
      #Third rotor rotates by 1 for every key being pressed
      if ($rotorCLetter -eq $rotorCNotch) {
        $rotorTrigger = $True
      }
      $rotorCLetter = $alphabet[($alphabet.IndexOf($rotorCLetter) + 1) % 26]
      #Check if rotorB needs to rotate
      if ($rotorTrigger) {
        $rotorTrigger = $False
        if ($rotorBLetter -eq $rotorBNotch) {
          $rotorTrigger = $True 
        }
        $rotorBLetter = $alphabet[($alphabet.IndexOf($rotorBLetter) + 1) % 26]
  
        #Check if rotorA needs to rotate
        if ($rotorTrigger) {
          $rotorTrigger = $False
          $rotorALetter = $alphabet[($alphabet.IndexOf($rotorALetter) + 1) % 26]
        }		 
      } else {
        #Check for double step sequence!
        if ($rotorBLetter -eq $rotorBNotch) {
          $rotorBLetter = $alphabet[($alphabet.IndexOf($rotorBLetter) + 1) % 26]
          $rotorALetter = $alphabet[($alphabet.IndexOf($rotorALetter) + 1) % 26]
        }
      }
        
      #Implement plugboard encryption!
      if ($plugboardDict.keys -contains $letter) {
        if ($plugboardDict[$letter] -ne "") {
          $encryptedLetter = $plugboardDict[$letter]
        }
      }
      #Rotors & Reflector Encryption
      $offsetA = $alphabet.IndexOf($rotorALetter)
      $offsetB = $alphabet.IndexOf($rotorBLetter)
      $offsetC = $alphabet.IndexOf($rotorCLetter)

      # Wheel 3 Encryption
      $pos = $alphabet.IndexOf($encryptedLetter)
      [string]$let = $rotorC[($pos + $offsetC)%26]
      $pos = $alphabet.IndexOf($let)
      [string]$encryptedLetter = $alphabet[($pos - $offsetC +26)%26]
      
      # Wheel 2 Encryption
      $pos = $alphabet.IndexOf($encryptedLetter)
      [string]$let = $rotorB[($pos + $offsetB)%26]
      $pos = $alphabet.IndexOf($let)
      [string]$encryptedLetter = $alphabet[($pos - $offsetB +26)%26]
      
      # Wheel 1 Encryption
      $pos = $alphabet.IndexOf($encryptedLetter)
      [string]$let = $rotorA[($pos + $offsetA)%26]
      $pos = $alphabet.IndexOf($let)
      [string]$encryptedLetter = $alphabet[($pos - $offsetA +26)%26]
      
      # Reflector encryption!
      if ($reflectorDict.keys -contains $encryptedLetter) {
        if ($reflectorDict[$encryptedLetter] -ne "") {
          [string]$encryptedLetter = $reflectorDict[$encryptedLetter]
        }
      }
      
      #Back through the rotors 
      # Wheel 1 Encryption
      $pos = $alphabet.IndexOf($encryptedLetter)
      [string]$let = $alphabet[($pos + $offsetA)%26]
      $pos = $rotorA.IndexOf($let)
      [string]$encryptedLetter = $alphabet[($pos - $offsetA +26)%26] 
      
      # Wheel 2 Encryption
      $pos = $alphabet.IndexOf($encryptedLetter)
      $let = $alphabet[($pos + $offsetB)%26]
      $pos = $rotorB.IndexOf($let)
      $encryptedLetter = $alphabet[($pos - $offsetB +26)%26]
      
      # Wheel 3 Encryption
      $pos = $alphabet.IndexOf($encryptedLetter)
      [string]$let = $alphabet[($pos + $offsetC)%26]
      $pos = $rotorC.IndexOf($let)
      [string]$encryptedLetter = $alphabet[($pos - $offsetC +26)%26]
      
      #Implement plugboard encryption!
      if ($plugboardDict.keys -contains $encryptedLetter) {
        if ($plugboardDict[$encryptedLetter] -ne "") {
          [string]$encryptedLetter = $plugboardDict[$encryptedLetter]
        }
      }
    }  
    $ciphertext = $ciphertext + $encryptedLetter
  }
  return $ciphertext
}

#Main Program Starts Here
Write-Host "  ##### Enigma Encoder #####"
Write-Host ""
$plaintext = Read-Host -Prompt "Enter text to encode or decode"
$ciphertext = encode $plaintext
Write-Host "Encoded text:" $ciphertext
