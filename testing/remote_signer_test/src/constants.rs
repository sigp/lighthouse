// Legit BLS pairs.
pub const PUBLIC_KEY_1: &str = "b7354252aa5bce27ab9537fd0158515935f3c3861419e1b4b6c8219b5dbd15fcf907bddf275442f3e32f904f79807a2a";
pub const SECRET_KEY_1: &str = "68081afeb7ad3e8d469f87010804c3e8d53ef77d393059a55132637206cc59ec";

pub const PUBLIC_KEY_1_BYTES: [u8; 48] = [
    183, 53, 66, 82, 170, 91, 206, 39, 171, 149, 55, 253, 1, 88, 81, 89, 53, 243, 195, 134, 20, 25,
    225, 180, 182, 200, 33, 155, 93, 189, 21, 252, 249, 7, 189, 223, 39, 84, 66, 243, 227, 47, 144,
    79, 121, 128, 122, 42,
];

pub const SECRET_KEY_1_BYTES: [u8; 32] = [
    104, 8, 26, 254, 183, 173, 62, 141, 70, 159, 135, 1, 8, 4, 195, 232, 213, 62, 247, 125, 57, 48,
    89, 165, 81, 50, 99, 114, 6, 204, 89, 236,
];

pub const PUBLIC_KEY_2: &str = "9324739760579527b4f8c34c5df42f9fd89f59fdbe8a01d58675769f60fec5da9b9c8d7a3203cf2217692e49e7b98d97";
pub const SECRET_KEY_2: &str = "45b5e876e5e57b23af3e86c37d708626cf1dcca6a650091bba2ddb3e0b7304ae";

pub const PUBLIC_KEY_3: &str = "8244ac66a8bffa0ce0af04d69ed7ed009951061259173a7c7ae1f25c049f0fcbbf2fad67b6d2b276a697315be755dac5";
pub const SECRET_KEY_3: &str = "1e52a4e54e89ccba813d5f902545749c356f6187341b4e765bf43ece401762f6";

// It is valid (from 0731e07e99a0b1c69f0de13ad65e5c374e72d0a997d43387ad70448485879ca1),
// But we are not uploading it.
pub const ABSENT_PUBLIC_KEY: &str = "827803e94e4b8d306735df9002465b310fabb39802341dc5c616a204e4e8dc7dbb6caa4733b5da54f8cdeec7788e7500";

// This is the public key of 0e5faaa97a63929cecb8597949ae148c0607f1b30bd057a7487efeb4c701fbf8.
pub const MISMATCHED_PUBLIC_KEY: &str = "83d40dfb1cbcf2a55c139faa3feec14bdae92dd485009ac8c5670d241f71c2ce064afa48dbaf091e16d0e4356038b948";

// The valid secret key is 3d703bd0dfdf2abb925b2d6bf1adf045ce8d93b8baff07e3313c5e150b043e89
pub const PUBLIC_KEY_FOR_INVALID_SECRET_KEY: &str = "aac313c0bc04880c4e9f4b0b69a9f310b09b9325027666cc7f255f88c7f35b82a82b2aa004c9be655b5696fea67f7300";
pub const INVALID_SECRET_KEY: &str = "WubbaLubbaDubDub";

// This is the public key of 34e62afe7c4402009a46bf8af574f9d6701c2cf72b3868eeeb59dfa6e7ff6bcf.
pub const SUB_DIR_NAME: &str = "aadbe2d5c0316dd3c9a522029f332cde578730e61d759685d7ad3bf1166c5f0bf094c3abc105384506f052e2b7a1bae0";

// Silly files with long names (96 chars) to fill your BLS raw file directory.
pub const SILLY_FILE_NAME_1: &str =
    "IAmAdamPrinceofEterniaDefenderofthesecretsoftheCastleGrayskullThisisCringermyfearlessfriendFabul";
pub const SILLY_CONTENT_1: &str = "HemanandtheMastersoftheUniverse";

pub const SILLY_FILE_NAME_2: &str =
    "InthenearfutureDocTerrorandhiscyborgcompanionHackerunleashtheirforcestoconquerEarthOnlyoneforcec";
pub const SILLY_CONTENT_2: &str = "Centurions";

pub const SILLY_FILE_NAME_3: &str =
    "OurworldisinperilGaiathespiritoftheearthcannolongerstandtheterribledestructionplaguingourplanetS";
pub const SILLY_CONTENT_3: &str = "CaptainPlanet";

// Taken from some random string.
pub const SIGNING_ROOT: &str = "b6bb8f3765f93f4f1e7c7348479289c9261399a3c6906685e320071a1a13955c";

pub const SIGNING_ROOT_BYTES: [u8; 32] = [
    182, 187, 143, 55, 101, 249, 63, 79, 30, 124, 115, 72, 71, 146, 137, 201, 38, 19, 153, 163,
    198, 144, 102, 133, 227, 32, 7, 26, 26, 19, 149, 92,
];

// Expected signature for the message 0xb6bb8f3765f93f4f1e7c7348479289c9261399a3c6906685e320071a1a13955c
// using 68081afeb7ad3e8d469f87010804c3e8d53ef77d393059a55132637206cc59ec as secret key
pub const EXPECTED_SIGNATURE_1: &str = "0xb5d0c01cef3b028e2c5f357c2d4b886f8e374d09dd660cd7dd14680d4f956778808b4d3b2ab743e890fc1a77ae62c3c90d613561b23c6adaeb5b0e288832304fddc08c7415080be73e556e8862a1b4d0f6aa8084e34a901544d5bb6aeed3a612";

pub const EXPECTED_SIGNATURE_1_BYTES: [u8; 96] = [
    181, 208, 192, 28, 239, 59, 2, 142, 44, 95, 53, 124, 45, 75, 136, 111, 142, 55, 77, 9, 221,
    102, 12, 215, 221, 20, 104, 13, 79, 149, 103, 120, 128, 139, 77, 59, 42, 183, 67, 232, 144,
    252, 26, 119, 174, 98, 195, 201, 13, 97, 53, 97, 178, 60, 106, 218, 235, 91, 14, 40, 136, 50,
    48, 79, 221, 192, 140, 116, 21, 8, 11, 231, 62, 85, 110, 136, 98, 161, 180, 208, 246, 170, 128,
    132, 227, 74, 144, 21, 68, 213, 187, 106, 238, 211, 166, 18,
];

// Expected signature for the message 0xb6bb8f3765f93f4f1e7c7348479289c9261399a3c6906685e320071a1a13955c
// using 45b5e876e5e57b23af3e86c37d708626cf1dcca6a650091bba2ddb3e0b7304ae as secret key
pub const EXPECTED_SIGNATURE_2: &str = "0xb6b63e3cecd0967d9f9b90e3ee113dfb21ecd3901dbc654ca69649ac5a0746758661306627f18bb6d7a6ea03ace069500ee79a28154c172dd71ffe4b711875e48b60466a90f3a4dcacdbc9b5f5434ad68c91e603fe1703324d83617f5270aead";

pub const EXPECTED_SIGNATURE_2_BYTES: [u8; 96] = [
    182, 182, 62, 60, 236, 208, 150, 125, 159, 155, 144, 227, 238, 17, 61, 251, 33, 236, 211, 144,
    29, 188, 101, 76, 166, 150, 73, 172, 90, 7, 70, 117, 134, 97, 48, 102, 39, 241, 139, 182, 215,
    166, 234, 3, 172, 224, 105, 80, 14, 231, 154, 40, 21, 76, 23, 45, 215, 31, 254, 75, 113, 24,
    117, 228, 139, 96, 70, 106, 144, 243, 164, 220, 172, 219, 201, 181, 245, 67, 74, 214, 140, 145,
    230, 3, 254, 23, 3, 50, 77, 131, 97, 127, 82, 112, 174, 173,
];

// Expected signature for the message 0xb6bb8f3765f93f4f1e7c7348479289c9261399a3c6906685e320071a1a13955c
// using 1e52a4e54e89ccba813d5f902545749c356f6187341b4e765bf43ece401762f6 as secret key
pub const EXPECTED_SIGNATURE_3: &str = "0x874f7d6d4174df1088ab40bd9a3c808554c55d6de1dffcacc7ef56c3ca22e20b52a23dd5bb6568a123b59df0bacef3de14d4c197a2fb2a5868a18c4b11f6d7957673d9a302bf6812b1d5df9b264504f682b43dfbcf4f9130cb5ebb9b8e3737de";

pub const EXPECTED_SIGNATURE_3_BYTES: [u8; 96] = [
    135, 79, 125, 109, 65, 116, 223, 16, 136, 171, 64, 189, 154, 60, 128, 133, 84, 197, 93, 109,
    225, 223, 252, 172, 199, 239, 86, 195, 202, 34, 226, 11, 82, 162, 61, 213, 187, 101, 104, 161,
    35, 181, 157, 240, 186, 206, 243, 222, 20, 212, 193, 151, 162, 251, 42, 88, 104, 161, 140, 75,
    17, 246, 215, 149, 118, 115, 217, 163, 2, 191, 104, 18, 177, 213, 223, 155, 38, 69, 4, 246,
    130, 180, 61, 251, 207, 79, 145, 48, 203, 94, 187, 155, 142, 55, 55, 222,
];

// These HAPPY_PATH constants were obtained running "sanity check" tests. i.e. Usign the non-remote way for producing the signature.
pub const HAPPY_PATH_BLOCK_SIGNATURE_C137: &str = "0x87c2a5bbd71d6277802e8bf5319b84c9fbb7441c4ce56dc39e721ba4371e7521a04a36c166c5cba37e8c645e91cc31fc02884bf44fdeb51c52173e642934fd3f3e8f72f53c2ec7da284630dc86e49da75cb2578761403ed24c3a8e4bccf33e4c";

pub const HAPPY_PATH_ATT_SIGNATURE_C137: &str = "0xada13507d81feb5a5057565f45abed9248be56a463efa944598090bdcdd61c3fa51bb5ef34f845100efe0c14dc0c0fa20d068a7ea4f14c3e9b43aa1c44f14cb73371e48338a90622b0bee4c3a988b726d3ad87ea8a111115a0d6e1e908c421d8";

pub const HAPPY_PATH_RANDAO_SIGNATURE_C137: &str = "0x8c5c88491486d0c4572e4043fd42b3f774778c6f9c44464b61272c9667d18f3ca894ae08344fcd7f6dd8b6954572b90a10ce7457367cecaa9f6ef7bf105aa2e79ae7e9568317d933ac2a8e45fb06f3edfc3f6f5881ca96c8eed0c2a83fa9bc2d";
