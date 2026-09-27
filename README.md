# IF4020 Tubes 2

## How to test
```shell
# Create a test message
echo "Hello, Cipher Module 6!" > sample.txt

# Encrypt the file using CBC mode with a 64-bit key
python3 main.py encrypt -i sample.txt -o sample.enc -k 0x1234567890ABCDEF -m CBC --iv 0x8765432187654321

# Decrypt the file
python3 main.py decrypt -i sample.enc -o sample_restored.txt -k 0x1234567890ABCDEF -m CBC --iv 0x8765432187654321

# Verify the restored text matches the original
cat sample_restored.txt
```

## Author 
1. Brian A. Hadian (13523048)
2. Zulfaqqar Nayaka Athadiansyah (13523094)
3. Azfa Radhiyya Hakim (13523115)