package com.zerotrace.service;

import com.zerotrace.dto.request.CreateWalletRequest;
import com.zerotrace.entity.User;
import com.zerotrace.entity.Wallet;
import com.zerotrace.repository.UserRepository;
import com.zerotrace.repository.WalletRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.*;
import org.bitcoinj.crypto.MnemonicUtils;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.web3j.crypto.Keys;
import org.web3j.crypto.ECKeyPair;
import org.web3j.crypto.Credentials;

@Service
@Transactional
public class WalletService {

    private static final Logger logger = LoggerFactory.getLogger(WalletService.class);
    private static final int MNEMONIC_WORD_COUNT = 24; // 256-bit entropy
    private static final String HD_PATH_BITCOIN = "m/84'/0'/0'/0/"; // BIP84 for SegWit
    private static final String HD_PATH_ETHEREUM = "m/44'/60'/0'/0/"; // BIP44 for Ethereum

    @Autowired
    private WalletRepository walletRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EncryptionService encryptionService;

    @Autowired
    private KeyManagementService keyManagementService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${crypto.wallet.security.wallet.max-per-user}")
    private int maxWalletsPerUser = 10;

    private final SecureRandom secureRandom = new SecureRandom();

    public Wallet createWallet(Long userId, CreateWalletRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        // Check wallet limit
        long existingWallets = walletRepository.countWalletsByUser(user);
        if (existingWallets >= maxWalletsPerUser) {
            throw new RuntimeException("Maximum wallet limit reached");
        }

        // Generate wallet keys based on currency type
        WalletKeys walletKeys = generateWalletKeys(request.getCurrencyType());

        // Create wallet entity
        Wallet wallet = new Wallet();
        wallet.setUser(user);
        wallet.setCurrencyType(request.getCurrencyType());
        wallet.setWalletName(request.getWalletName() != null ?
                request.getWalletName() :
                request.getCurrencyType() + " Wallet " + (existingWallets + 1));

        // Set wallet address
        wallet.setWalletAddress(walletKeys.address);
        wallet.setPublicKey(walletKeys.publicKey);

        // Encrypt and store private key and mnemonic
        try {
            String encryptedPrivateKey = encryptionService.encryptPrivateKey(
                    walletKeys.privateKey,
                    user.getEmail(),
                    wallet.getWalletAddress()
            );
            wallet.setEncryptedPrivateKey(encryptedPrivateKey);

            if (walletKeys.mnemonic != null) {
                String encryptedMnemonic = encryptionService.encryptSensitiveData(
                        walletKeys.mnemonic,
                        user.getEmail()
                );
                wallet.setEncryptedMnemonic(encryptedMnemonic);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to encrypt wallet keys", e);
        }

        // Set derivation path
        wallet.setDerivationPath(walletKeys.derivationPath);
        wallet.setWalletIndex(0);

        // Configure multi-signature if requested
        if (Boolean.TRUE.equals(request.getEnableMultiSignature())) {
            wallet.setMultiSignatureEnabled(true);
            wallet.setRequiredSignatures(request.getRequiredSignatures());
            wallet.setAuthorizedSigners(String.join(",", request.getAuthorizedSigners()));
        }

        // Set spending limits
        if (request.getDailyLimit() != null) {
            wallet.setDailyLimit(request.getDailyLimit());
            wallet.setDailyLimitReset(LocalDateTime.now().plusDays(1));
        }

        // Configure cold storage
        wallet.setColdStorage(Boolean.TRUE.equals(request.getColdStorage()));
        wallet.setHardwareWalletId(request.getHardwareWalletId());

        // Set security level based on configuration
        int securityLevel = calculateSecurityLevel(wallet);
        wallet.setSecurityLevel(securityLevel);

        // Save wallet
        wallet = walletRepository.save(wallet);

        logger.info("Created {} wallet for user {}", request.getCurrencyType(), userId);
        return wallet;
    }

    public Page<Wallet> getUserWallets(Long userId, Pageable pageable) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return walletRepository.findAll(
                (root, query, criteriaBuilder) -> criteriaBuilder.and(
                        criteriaBuilder.equal(root.get("user"), user),
                        criteriaBuilder.notEqual(root.get("walletStatus"), Wallet.WalletStatus.ARCHIVED)
                ),
                pageable
        );
    }

    public Wallet getWalletByIdAndUser(Long walletId, Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return walletRepository.findByIdAndUser(walletId, user)
                .orElseThrow(() -> new RuntimeException("Wallet not found"));
    }

    public Wallet updateWallet(Long walletId, Long userId, Map<String, Object> updates) {
        Wallet wallet = getWalletByIdAndUser(walletId, userId);

        // Update allowed fields
        if (updates.containsKey("walletName")) {
            wallet.setWalletName((String) updates.get("walletName"));
        }

        if (updates.containsKey("dailyLimit")) {
            BigDecimal dailyLimit = new BigDecimal(updates.get("dailyLimit").toString());
            wallet.setDailyLimit(dailyLimit);
        }

        if (updates.containsKey("multiSignatureEnabled")) {
            wallet.setMultiSignatureEnabled((Boolean) updates.get("multiSignatureEnabled"));
        }

        // Recalculate security level
        wallet.setSecurityLevel(calculateSecurityLevel(wallet));

        return walletRepository.save(wallet);
    }

    public Map<String, String> createWalletBackup(Long walletId, Long userId, String password) {
        Wallet wallet = getWalletByIdAndUser(walletId, userId);
        User user = wallet.getUser();

        // Verify password
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new RuntimeException("Invalid password");
        }

        try {
            // Decrypt mnemonic
            String mnemonic = encryptionService.decryptSensitiveData(
                    wallet.getEncryptedMnemonic(),
                    user.getEmail()
            );

            // Mark backup as created
            wallet.setBackupCreated(true);
            walletRepository.save(wallet);

            Map<String, String> backup = new HashMap<>();
            backup.put("mnemonic", mnemonic);
            backup.put("walletAddress", wallet.getWalletAddress());
            backup.put("currencyType", wallet.getCurrencyType().toString());
            backup.put("derivationPath", wallet.getDerivationPath());
            backup.put("backupDate", LocalDateTime.now().toString());

            return backup;
        } catch (Exception e) {
            throw new RuntimeException("Failed to create wallet backup", e);
        }
    }

    public boolean verifyWalletBackup(Long walletId, Long userId, String backupPhrase) {
        Wallet wallet = getWalletByIdAndUser(walletId, userId);
        User user = wallet.getUser();

        try {
            // Decrypt stored mnemonic
            String storedMnemonic = encryptionService.decryptSensitiveData(
                    wallet.getEncryptedMnemonic(),
                    user.getEmail()
            );

            // Verify backup phrase matches
            boolean verified = storedMnemonic.equals(backupPhrase);

            if (verified) {
                wallet.setBackupVerified(true);
                walletRepository.save(wallet);
            }

            return verified;
        } catch (Exception e) {
            logger.error("Failed to verify wallet backup", e);
            return false;
        }
    }

    public Map<String, Object> getWalletBalance(Long walletId, Long userId, boolean refresh) {
        Wallet wallet = getWalletByIdAndUser(walletId, userId);

        if (refresh) {
            // TODO: Implement blockchain balance refresh
            // This would connect to blockchain nodes to get real-time balance
            updateWalletBalanceFromBlockchain(wallet);
        }

        Map<String, Object> balance = new HashMap<>();
        balance.put("balance", wallet.getBalance());
        balance.put("pendingBalance", wallet.getPendingBalance());
        balance.put("totalBalance", wallet.getBalance().add(wallet.getPendingBalance()));
        balance.put("currency", wallet.getCurrencyType());
        balance.put("lastSync", wallet.getLastSyncDate());

        return balance;
    }

    public void lockWallet(Long walletId, Long userId) {
        Wallet wallet = getWalletByIdAndUser(walletId, userId);
        wallet.setWalletStatus(Wallet.WalletStatus.LOCKED);
        walletRepository.save(wallet);
    }

    public void unlockWallet(Long walletId, Long userId, String password) {
        Wallet wallet = getWalletByIdAndUser(walletId, userId);
        User user = wallet.getUser();

        // Verify password
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new RuntimeException("Invalid password");
        }

        wallet.setWalletStatus(Wallet.WalletStatus.ACTIVE);
        walletRepository.save(wallet);
    }

    public void archiveWallet(Long walletId, Long userId, String password, String reason) {
        Wallet wallet = getWalletByIdAndUser(walletId, userId);
        User user = wallet.getUser();

        // Verify password
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new RuntimeException("Invalid password");
        }

        // Check if wallet has zero balance
        if (wallet.getBalance().compareTo(BigDecimal.ZERO) > 0) {
            throw new RuntimeException("Cannot archive wallet with non-zero balance");
        }

        wallet.setWalletStatus(Wallet.WalletStatus.ARCHIVED);
        walletRepository.save(wallet);
    }

    public List<Map<String, String>> getSupportedCurrencies() {
        List<Map<String, String>> currencies = new ArrayList<>();

        for (Wallet.CurrencyType currency : Wallet.CurrencyType.values()) {
            Map<String, String> currencyInfo = new HashMap<>();
            currencyInfo.put("code", currency.name());
            currencyInfo.put("name", getCurrencyFullName(currency));
            currencyInfo.put("type", getCurrencyType(currency));
            currencies.add(currencyInfo);
        }

        return currencies;
    }

    public Map<String, Object> exportWalletData(Long walletId, Long userId, String format) {
        Wallet wallet = getWalletByIdAndUser(walletId, userId);

        Map<String, Object> exportData = new HashMap<>();
        exportData.put("walletAddress", wallet.getWalletAddress());
        exportData.put("currency", wallet.getCurrencyType());
        exportData.put("walletName", wallet.getWalletName());
        exportData.put("createdDate", wallet.getCreatedDate());

        if ("json".equalsIgnoreCase(format)) {
            exportData.put("format", "json");
            exportData.put("version", "1.0");
        } else if ("csv".equalsIgnoreCase(format)) {
            exportData.put("format", "csv");
            // Convert to CSV format
            String csvData = convertToCsv(exportData);
            exportData.put("data", csvData);
        }

        return exportData;
    }

    // Helper methods
    private WalletKeys generateWalletKeys(Wallet.CurrencyType currencyType) {
        try {
            switch (currencyType) {
                case BTC:
                    return generateBitcoinWallet();
                case ETH:
                case USDT:
                case USDC:
                case BNB:
                case MATIC:
                    return generateEthereumBasedWallet();
                case ADA:
                    return generateCardanoWallet();
                case SOL:
                    return generateSolanaWallet();
                case DOT:
                    return generatePolkadotWallet();
                case AVAX:
                    return generateAvalancheWallet();
                default:
                    throw new RuntimeException("Unsupported currency type: " + currencyType);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate wallet keys", e);
        }
    }

    private WalletKeys generateBitcoinWallet() throws Exception {
        // Generate mnemonic
        byte[] entropy = new byte[32];
        secureRandom.nextBytes(entropy);
        String mnemonic = MnemonicUtils.generateMnemonic(entropy);

        // Generate seed from mnemonic
        byte[] seed = MnemonicUtils.generateSeed(mnemonic, "");

        // Generate master key
        DeterministicKey masterKey = HDKeyDerivation.createMasterPrivateKey(seed);

        // Derive key using BIP84 path for SegWit
        DeterministicKey accountKey = HDKeyDerivation.deriveChildKey(masterKey, 84 | 0x80000000);
        accountKey = HDKeyDerivation.deriveChildKey(accountKey, 0x80000000);
        accountKey = HDKeyDerivation.deriveChildKey(accountKey, 0x80000000);
        DeterministicKey externalKey = HDKeyDerivation.deriveChildKey(accountKey, 0);
        DeterministicKey addressKey = HDKeyDerivation.deriveChildKey(externalKey, 0);

        // Generate address (simplified - in production use proper Bitcoin library)
        String address = generateBitcoinAddress(addressKey.getPubKey());

        WalletKeys keys = new WalletKeys();
        keys.address = address;
        keys.privateKey = addressKey.getPrivateKeyAsHex();
        keys.publicKey = addressKey.getPublicKeyAsHex();
        keys.mnemonic = mnemonic;
        keys.derivationPath = HD_PATH_BITCOIN;

        return keys;
    }

    private WalletKeys generateEthereumBasedWallet() throws Exception {
        // Generate mnemonic
        byte[] entropy = new byte[32];
        secureRandom.nextBytes(entropy);
        String mnemonic = MnemonicUtils.generateMnemonic(entropy);

        // Generate seed from mnemonic
        byte[] seed = MnemonicUtils.generateSeed(mnemonic, "");

        // Generate key pair
        ECKeyPair ecKeyPair = ECKeyPair.create(seed);
        Credentials credentials = Credentials.create(ecKeyPair);

        WalletKeys keys = new WalletKeys();
        keys.address = credentials.getAddress();
        keys.privateKey = credentials.getEcKeyPair().getPrivateKey().toString(16);
        keys.publicKey = credentials.getEcKeyPair().getPublicKey().toString(16);
        keys.mnemonic = mnemonic;
        keys.derivationPath = HD_PATH_ETHEREUM;

        return keys;
    }

    private WalletKeys generateCardanoWallet() throws Exception {
        // Simplified implementation - in production use Cardano-specific libraries
        return generateGenericWallet("addr1");
    }

    private WalletKeys generateSolanaWallet() throws Exception {
        // Simplified implementation - in production use Solana-specific libraries
        return generateGenericWallet("sol");
    }

    private WalletKeys generatePolkadotWallet() throws Exception {
        // Simplified implementation - in production use Polkadot-specific libraries
        return generateGenericWallet("dot");
    }

    private WalletKeys generateAvalancheWallet() throws Exception {
        // Avalanche uses same format as Ethereum
        return generateEthereumBasedWallet();
    }

    private WalletKeys generateGenericWallet(String prefix) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, secureRandom);
        KeyPair keyPair = keyGen.generateKeyPair();

        WalletKeys keys = new WalletKeys();
        keys.address = prefix + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(keyPair.getPublic().getEncoded()).substring(0, 40);
        keys.privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
        keys.publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
        keys.mnemonic = generateMnemonicPhrase();
        keys.derivationPath = "m/44'/0'/0'/0/0";

        return keys;
    }

    private String generateBitcoinAddress(byte[] publicKey) {
        // Simplified - in production use proper Bitcoin address generation
        return "bc1q" + Base64.getUrlEncoder().withoutPadding()
                .encodeToString(publicKey).substring(0, 39).toLowerCase();
    }

    private String generateMnemonicPhrase() {
        // Generate 24-word mnemonic
        byte[] entropy = new byte[32];
        secureRandom.nextBytes(entropy);
        return MnemonicUtils.generateMnemonic(entropy);
    }

    private int calculateSecurityLevel(Wallet wallet) {
        int level = 1;

        if (wallet.getBackupCreated()) level++;
        if (wallet.getBackupVerified()) level++;
        if (wallet.getMultiSignatureEnabled()) level += 2;
        if (wallet.getColdStorage()) level += 2;
        if (wallet.getDailyLimit() != null) level++;

        return Math.min(level, 10); // Max security level is 10
    }

    private void updateWalletBalanceFromBlockchain(Wallet wallet) {
        // TODO: Implement blockchain integration
        // This would connect to various blockchain nodes/APIs to get real-time balance
        wallet.setLastSyncDate(LocalDateTime.now());
        walletRepository.save(wallet);
    }

    private String getCurrencyFullName(Wallet.CurrencyType currency) {
        switch (currency) {
            case BTC: return "Bitcoin";
            case ETH: return "Ethereum";
            case USDT: return "Tether USD";
            case USDC: return "USD Coin";
            case BNB: return "Binance Coin";
            case ADA: return "Cardano";
            case SOL: return "Solana";
            case DOT: return "Polkadot";
            case MATIC: return "Polygon";
            case AVAX: return "Avalanche";
            default: return currency.name();
        }
    }

    private String getCurrencyType(Wallet.CurrencyType currency) {
        switch (currency) {
            case USDT:
            case USDC:
                return "stablecoin";
            case BTC:
            case ETH:
            case BNB:
            case ADA:
            case SOL:
            case DOT:
            case MATIC:
            case AVAX:
                return "cryptocurrency";
            default:
                return "unknown";
        }
    }

    private String convertToCsv(Map<String, Object> data) {
        StringBuilder csv = new StringBuilder();
        csv.append("Field,Value\n");
        for (Map.Entry<String, Object> entry : data.entrySet()) {
            csv.append(entry.getKey()).append(",").append(entry.getValue()).append("\n");
        }
        return csv.toString();
    }

    // Inner class for wallet keys
    private static class WalletKeys {
        String address;
        String privateKey;
        String publicKey;
        String mnemonic;
        String derivationPath;
    }
}