import re

def identify_hash(hash_value):
    """
    Identify the type of hash based on its characteristics
    """
    # Remove any whitespace
    hash_value = hash_value.strip()
    
    # Special patterns that need specific format checking
    special_patterns = {
        'Bcrypt': r'^\$2[abxy]\$\d{2}\$[A-Za-z0-9./]{53}$',
        'PHPass': r'^\$P\$[A-Za-z0-9./]{31}$',
        'Drupal7': r'^\$S\$[A-Za-z0-9./]{52}$',
        'Joomla': r'^[A-Za-z0-9./]{32}:[A-Za-z0-9./]{32}$',
        'MySQL': r'^[0-9A-F]{40}$',
        'DomainCachedCredentials': r'^[0-9a-f]{32}:[0-9a-f]{32}$',
        'IPBoard': r'^[a-f0-9]{32}:[a-z0-9]{8}$',
        'PHPBB3': r'^\$H\$[A-Za-z0-9./]{31}$',
        'WordPress': r'^\$P\$[A-Za-z0-9./]{31}$',
        'Argon2': r'^\$argon2[id]\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$',
        'Scrypt': r'^\$scrypt\$[A-Za-z0-9./]+$',
        'Unix-SHA256': r'^\$5\$[A-Za-z0-9./]+\$[A-Za-z0-9./]{43}$',
        'Unix-SHA512': r'^\$6\$[A-Za-z0-9./]+\$[A-Za-z0-9./]{86}$',
        'MD5-Unix': r'^\$1\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}$',
        'MD5-APR1': r'^\$apr1\$[A-Za-z0-9./]{8}\$[A-Za-z0-9./]{22}$'
    }
    
    # Check special patterns first
    for hash_type, pattern in special_patterns.items():
        if re.match(pattern, hash_value):
            return [hash_type]
    
    # Convert to lowercase for standard hash patterns
    hash_value = hash_value.lower()
    
    # Dictionary of standard hash types and their characteristics
    hash_patterns = {
        'MD5': (r'^[a-f0-9]{32}$', 32),
        'MD4': (r'^[a-f0-9]{32}$', 32),
        'MD2': (r'^[a-f0-9]{32}$', 32),
        'SHA-1': (r'^[a-f0-9]{40}$', 40),
        'SHA-256': (r'^[a-f0-9]{64}$', 64),
        'SHA-384': (r'^[a-f0-9]{96}$', 96),
        'SHA-512': (r'^[a-f0-9]{128}$', 128),
        'SHA-224': (r'^[a-f0-9]{56}$', 56),
        'SHA3-224': (r'^[a-f0-9]{56}$', 56),
        'SHA3-256': (r'^[a-f0-9]{64}$', 64),
        'SHA3-384': (r'^[a-f0-9]{96}$', 96),
        'SHA3-512': (r'^[a-f0-9]{128}$', 128),
        'RIPEMD-128': (r'^[a-f0-9]{32}$', 32),
        'RIPEMD-160': (r'^[a-f0-9]{40}$', 40),
        'RIPEMD-256': (r'^[a-f0-9]{64}$', 64),
        'RIPEMD-320': (r'^[a-f0-9]{80}$', 80),
        'Whirlpool': (r'^[a-f0-9]{128}$', 128),
        'Tiger-128': (r'^[a-f0-9]{32}$', 32),
        'Tiger-160': (r'^[a-f0-9]{40}$', 40),
        'Tiger-192': (r'^[a-f0-9]{48}$', 48),
        'Snefru-128': (r'^[a-f0-9]{32}$', 32),
        'Snefru-256': (r'^[a-f0-9]{64}$', 64),
        'GOST': (r'^[a-f0-9]{64}$', 64),
        'GOST-CRYPTO': (r'^[a-f0-9]{64}$', 64),
        'ADLER-32': (r'^[a-f0-9]{8}$', 8),
        'CRC-32': (r'^[a-f0-9]{8}$', 8),
        'CRC-32B': (r'^[a-f0-9]{8}$', 8),
        'FNV-32': (r'^[a-f0-9]{8}$', 8),
        'FNV-64': (r'^[a-f0-9]{16}$', 16),
        'FNV-128': (r'^[a-f0-9]{32}$', 32),
        'FNV-256': (r'^[a-f0-9]{64}$', 64),
        'FNV-512': (r'^[a-f0-9]{128}$', 128),
        'FNV-1024': (r'^[a-f0-9]{256}$', 256),
        'Blake2b': (r'^[a-f0-9]{128}$', 128),
        'Blake2s': (r'^[a-f0-9]{64}$', 64),
        'MD6': (r'^[a-f0-9]{128}$', 128),
        'SHAKE-128': (r'^[a-f0-9]{64}$', 64),
        'SHAKE-256': (r'^[a-f0-9]{128}$', 128),
        'KangarooTwelve': (r'^[a-f0-9]{64}$', 64),
        'MarsupilamiFourteen': (r'^[a-f0-9]{128}$', 128),
        'LM': (r'^[a-f0-9]{32}$', 32),
        'NTLM': (r'^[a-f0-9]{32}$', 32),
        'NetNTLMv1': (r'^[a-f0-9]{48}$', 48),
        'NetNTLMv2': (r'^[a-f0-9]{64}$', 64),
        'HMAC-MD5': (r'^[a-f0-9]{32}$', 32),
        'HMAC-SHA1': (r'^[a-f0-9]{40}$', 40),
        'HMAC-SHA256': (r'^[a-f0-9]{64}$', 64),
        'HMAC-SHA512': (r'^[a-f0-9]{128}$', 128)
    }
    
    possible_hashes = []
    
    # Check each hash pattern
    for hash_type, (pattern, length) in hash_patterns.items():
        if len(hash_value) == length and re.match(pattern, hash_value):
            possible_hashes.append(hash_type)
    
    return possible_hashes

def main():
    print("\nSupported hash types:")
    print("1. Standard hashes (MD5, SHA family, RIPEMD family, etc.)")
    print("2. Password hashes (Bcrypt, PHPass, Argon2, Scrypt, etc.)")
    print("3. Unix password hashes (SHA-256, SHA-512, MD5-Unix)")
    print("4. Application-specific hashes (WordPress, Drupal, Joomla)")
    print("5. Checksum hashes (ADLER-32, CRC-32, FNV family)")
    print("6. Windows hashes (LM, NTLM, NetNTLMv1/v2)")
    print("7. HMAC variants\n")
    
    while True:
        # Get hash input from user
        hash_input = input("\nEnter the hash value (or 'q' to quit): ")
        
        if hash_input.lower() == 'q':
            print("Goodbye!")
            break
        
        # Identify the hash type
        possible_types = identify_hash(hash_input)
        
        if possible_types:
            print("\nPossible hash types:")
            for hash_type in possible_types:
                print(f"- {hash_type}")
        else:
            print("\nNo matching hash type found or invalid hash value.")
        
        print("\nNote: Some hash types may have the same length,")
        print("so multiple possibilities might be shown.")

if __name__ == "__main__":
    print("Hash Type Identifier")
    print("===================")
    main()
