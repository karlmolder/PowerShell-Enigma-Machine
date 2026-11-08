# PowerShell Enigma Machine

A PowerShell implementation of the German Enigma machine cipher. It can encode or decode text using configurable rotors, reflector, ring settings, rotor starting positions, and plugboard connections.

This project is a PowerShell conversion of the Enigma encoder example from [101 Computing](https://www.101computing.net/enigma-encoder/).

## Requirements

- Windows PowerShell or PowerShell 7+
- No external modules are required

## Run

Open PowerShell in the repository directory and run:

```powershell
.\enigma.ps1
```

Enter a message at the prompt. The program displays the encoded text. Enter the resulting text again with the same settings to decode it. Press Enter on an empty prompt to exit.

## Configure the Enigma

Edit the settings near the top of `enigma.ps1`:

```powershell
$rotors = @("I", "II", "III")
$reflector = "UKW-B"
$ringSettings = "ABC"
$ringPositions = "DEF"
$plugboard = "AT BS DE FM IR KN LZ OW PV XY"
```

- **Rotors:** Choose three rotors in left-to-right order. Available rotors are I, II, III, IV, and V.
- **Reflector:** Choose `UKW-B` or `UKW-C`.
- **Ring settings:** Three letters, one for each rotor.
- **Ring positions:** The initial displayed position of each rotor, left to right.
- **Plugboard:** Space-separated pairs of letters, such as `"AB CD EF"`. Each letter should appear in no more than one pair.

Use the same settings and starting positions to reverse an encoded message. Rotor positions reset to the configured starting positions each time you submit a message.

## Notes

- Letters are converted to uppercase.
- Non-letter characters are passed through unchanged and do not advance the rotors.
- The implementation includes the Enigma double-stepping behavior.
- This is an educational historical cipher implementation, not modern secure encryption. Do not use it to protect sensitive information.

## License

No license has been specified for this repository. Unless a license is added, standard copyright restrictions apply.
