/*
 Navicat Premium Dump SQL

 Source Server         : MySQL
 Source Server Type    : MySQL
 Source Server Version : 100315 (10.3.15-MariaDB)
 Source Host           : localhost:3306
 Source Schema         : db_allegro_prestashop_sync

 Target Server Type    : MySQL
 Target Server Version : 100315 (10.3.15-MariaDB)
 File Encoding         : 65001

 Date: 14/01/2026 00:04:55
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for allegro_credentials
-- ----------------------------
DROP TABLE IF EXISTS `allegro_credentials`;
CREATE TABLE `allegro_credentials`  (
  `id` int UNSIGNED NOT NULL AUTO_INCREMENT,
  `app_user_id` int UNSIGNED NOT NULL,
  `client_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `client_secret` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `unique_user`(`app_user_id` ASC) USING BTREE,
  CONSTRAINT `allegro_credentials_ibfk_1` FOREIGN KEY (`app_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of allegro_credentials
-- ----------------------------
INSERT INTO `allegro_credentials` VALUES (1, 1, '36c47635bb1d4977b49473adccb36da9', 'c413UWvV0nhyAh8hAdR0Dq2315W6HoA3WuP98WxZ6ARmuc50oEJYIgS3m7QmbNIP', '2026-01-04 02:02:42', '2026-01-04 02:02:42');

-- ----------------------------
-- Table structure for category_cache
-- ----------------------------
DROP TABLE IF EXISTS `category_cache`;
CREATE TABLE `category_cache`  (
  `id` int UNSIGNED NOT NULL AUTO_INCREMENT,
  `app_user_id` int UNSIGNED NOT NULL,
  `category_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `category_id` int NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `unique_user_category_name`(`app_user_id` ASC, `category_name` ASC) USING BTREE,
  INDEX `idx_category_name`(`category_name` ASC) USING BTREE,
  INDEX `idx_category_id`(`category_id` ASC) USING BTREE,
  INDEX `idx_user_category`(`app_user_id` ASC, `category_name` ASC) USING BTREE,
  CONSTRAINT `category_cache_ibfk_1` FOREIGN KEY (`app_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 464 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of category_cache
-- ----------------------------
INSERT INTO `category_cache` VALUES (303, 1, 'sport i turystyka', 2832, '2026-01-13 13:54:12', '2026-01-13 13:54:12');
INSERT INTO `category_cache` VALUES (304, 1, 'zdrowie', 2833, '2026-01-13 13:54:13', '2026-01-13 13:54:13');
INSERT INTO `category_cache` VALUES (305, 1, 'firma i usługi', 2834, '2026-01-13 13:54:15', '2026-01-13 13:54:15');
INSERT INTO `category_cache` VALUES (306, 1, 'motoryzacja', 2835, '2026-01-13 13:54:17', '2026-01-13 13:54:17');
INSERT INTO `category_cache` VALUES (307, 1, 'dziecko', 2836, '2026-01-13 13:54:18', '2026-01-13 13:54:18');
INSERT INTO `category_cache` VALUES (308, 1, 'dom i ogrod', 2837, '2026-01-13 13:54:19', '2026-01-13 13:54:19');
INSERT INTO `category_cache` VALUES (309, 1, 'kolekcje i sztuka', 2838, '2026-01-13 13:54:20', '2026-01-13 13:54:20');
INSERT INTO `category_cache` VALUES (310, 1, 'komputery', 2839, '2026-01-13 13:54:21', '2026-01-13 13:54:21');
INSERT INTO `category_cache` VALUES (311, 1, 'rtv i agd', 2840, '2026-01-13 13:54:22', '2026-01-13 13:54:22');
INSERT INTO `category_cache` VALUES (312, 1, 'fotografia', 2841, '2026-01-13 13:54:23', '2026-01-13 13:54:23');
INSERT INTO `category_cache` VALUES (313, 1, 'rowery i akcesoria', 2842, '2026-01-13 13:54:24', '2026-01-13 13:54:24');
INSERT INTO `category_cache` VALUES (314, 1, 'sprzet i wyposazenie medyczne', 2843, '2026-01-13 13:54:25', '2026-01-13 13:54:25');
INSERT INTO `category_cache` VALUES (315, 1, 'przemysł', 2844, '2026-01-13 13:54:26', '2026-01-13 13:54:26');
INSERT INTO `category_cache` VALUES (316, 1, 'turystyka', 2845, '2026-01-13 13:54:27', '2026-01-13 13:54:27');
INSERT INTO `category_cache` VALUES (317, 1, 'narzedzia i sprzet warsztatowy', 2846, '2026-01-13 13:54:28', '2026-01-13 13:54:28');
INSERT INTO `category_cache` VALUES (318, 1, 'akcesoria dla mamy i dziecka', 2847, '2026-01-13 13:54:29', '2026-01-13 13:54:29');
INSERT INTO `category_cache` VALUES (319, 1, 'karmienie dziecka', 2848, '2026-01-13 13:54:30', '2026-01-13 13:54:30');
INSERT INTO `category_cache` VALUES (320, 1, 'telefony i akcesoria', 2849, '2026-01-13 13:54:31', '2026-01-13 13:54:31');
INSERT INTO `category_cache` VALUES (321, 1, 'skating, slackline', 2850, '2026-01-13 13:54:32', '2026-01-13 13:54:32');
INSERT INTO `category_cache` VALUES (322, 1, 'wyposazenie i akcesoria samochodowe', 2851, '2026-01-13 13:54:33', '2026-01-13 13:54:33');
INSERT INTO `category_cache` VALUES (323, 1, 'wyposazenie', 2852, '2026-01-13 13:54:34', '2026-01-13 13:54:34');
INSERT INTO `category_cache` VALUES (324, 1, 'sprzet estradowy, studyjny i dj-ski', 2853, '2026-01-13 13:54:35', '2026-01-13 13:54:35');
INSERT INTO `category_cache` VALUES (325, 1, 'biuro i reklama', 2854, '2026-01-13 13:54:36', '2026-01-13 13:54:36');
INSERT INTO `category_cache` VALUES (326, 1, 'budownictwo i akcesoria', 2855, '2026-01-13 13:54:37', '2026-01-13 13:54:37');
INSERT INTO `category_cache` VALUES (327, 1, 'narzedzia', 2856, '2026-01-13 13:54:38', '2026-01-13 13:54:38');
INSERT INTO `category_cache` VALUES (328, 1, 'zdrowie i higiena', 2857, '2026-01-13 13:54:39', '2026-01-13 13:54:39');
INSERT INTO `category_cache` VALUES (329, 1, 'kolekcje', 2858, '2026-01-13 13:54:40', '2026-01-13 13:54:40');
INSERT INTO `category_cache` VALUES (330, 1, 'elektronika sportowa', 2859, '2026-01-13 13:54:41', '2026-01-13 13:54:41');
INSERT INTO `category_cache` VALUES (331, 1, 'czesci do laptopow', 2860, '2026-01-13 13:54:42', '2026-01-13 13:54:42');
INSERT INTO `category_cache` VALUES (332, 1, 'akcesoria (laptop, pc)', 2861, '2026-01-13 13:54:43', '2026-01-13 13:54:43');
INSERT INTO `category_cache` VALUES (333, 1, 'laptopy', 2862, '2026-01-13 13:54:44', '2026-01-13 13:54:44');
INSERT INTO `category_cache` VALUES (334, 1, 'elektronika', 2863, '2026-01-13 13:54:45', '2026-01-13 13:54:45');
INSERT INTO `category_cache` VALUES (335, 1, 'podzespoły komputerowe', 2864, '2026-01-13 13:54:46', '2026-01-13 13:54:46');
INSERT INTO `category_cache` VALUES (336, 1, 'zasilanie aparatow', 2865, '2026-01-13 13:54:47', '2026-01-13 13:54:47');
INSERT INTO `category_cache` VALUES (338, 1, 'specjalistyczny sprzet medyczny', 2867, '2026-01-13 13:54:49', '2026-01-13 13:54:49');
INSERT INTO `category_cache` VALUES (339, 1, 'przemysł energetyczny', 2868, '2026-01-13 13:54:50', '2026-01-13 13:54:50');
INSERT INTO `category_cache` VALUES (340, 1, 'serwery i akcesoria', 2869, '2026-01-13 13:54:51', '2026-01-13 13:54:51');
INSERT INTO `category_cache` VALUES (342, 1, 'agd drobne', 2871, '2026-01-13 13:54:53', '2026-01-13 13:54:53');
INSERT INTO `category_cache` VALUES (343, 1, 'diagnostyka i pomiary', 2872, '2026-01-13 13:54:54', '2026-01-13 13:54:54');
INSERT INTO `category_cache` VALUES (344, 1, 'internet', 2873, '2026-01-13 13:54:55', '2026-01-13 13:54:55');
INSERT INTO `category_cache` VALUES (345, 1, 'sprzet optyczny', 2874, '2026-01-13 13:54:56', '2026-01-13 13:54:56');
INSERT INTO `category_cache` VALUES (346, 1, 'sprzet car audio', 2875, '2026-01-13 13:54:57', '2026-01-13 13:54:57');
INSERT INTO `category_cache` VALUES (347, 1, 'akcesoria dla mamy', 2876, '2026-01-13 13:54:58', '2026-01-13 13:54:58');
INSERT INTO `category_cache` VALUES (348, 1, 'podgrzewacze', 2877, '2026-01-13 13:54:59', '2026-01-13 13:54:59');
INSERT INTO `category_cache` VALUES (349, 1, 'sprzet audio dla domu', 2878, '2026-01-13 13:55:00', '2026-01-13 13:55:00');
INSERT INTO `category_cache` VALUES (350, 1, 'powerbanki', 2879, '2026-01-13 13:55:01', '2026-01-13 13:55:01');
INSERT INTO `category_cache` VALUES (351, 1, 'kamery', 2880, '2026-01-13 13:55:02', '2026-01-13 13:55:02');
INSERT INTO `category_cache` VALUES (353, 1, 'ogien i ciepło', 2882, '2026-01-13 13:55:05', '2026-01-13 13:55:05');
INSERT INTO `category_cache` VALUES (354, 1, 'czujniki i kamery cofania', 2883, '2026-01-13 13:55:06', '2026-01-13 13:55:06');
INSERT INTO `category_cache` VALUES (355, 1, 'inteligentny dom', 2884, '2026-01-13 13:55:07', '2026-01-13 13:55:07');
INSERT INTO `category_cache` VALUES (356, 1, 'odziez', 2885, '2026-01-13 13:55:08', '2026-01-13 13:55:08');
INSERT INTO `category_cache` VALUES (357, 1, 'akcesoria gsm', 2886, '2026-01-13 13:55:09', '2026-01-13 13:55:09');
INSERT INTO `category_cache` VALUES (358, 1, 'akcesoria', 2887, '2026-01-13 13:55:10', '2026-01-13 13:55:10');
INSERT INTO `category_cache` VALUES (359, 1, 'kable, przewody i wtyki', 2888, '2026-01-13 13:55:11', '2026-01-13 13:55:11');
INSERT INTO `category_cache` VALUES (360, 1, 'pakowanie i wysyłka', 2889, '2026-01-13 13:55:12', '2026-01-13 13:55:12');
INSERT INTO `category_cache` VALUES (361, 1, 'ogrzewanie', 2890, '2026-01-13 13:55:13', '2026-01-13 13:55:13');
INSERT INTO `category_cache` VALUES (362, 1, 'spawarki', 2891, '2026-01-13 13:55:14', '2026-01-13 13:55:14');
INSERT INTO `category_cache` VALUES (363, 1, 'tablety', 2892, '2026-01-13 13:55:15', '2026-01-13 13:55:15');
INSERT INTO `category_cache` VALUES (364, 1, 'artykuły higieniczne', 2893, '2026-01-13 13:55:16', '2026-01-13 13:55:16');
INSERT INTO `category_cache` VALUES (365, 1, 'radiokomunikacja', 2894, '2026-01-13 13:55:17', '2026-01-13 13:55:17');
INSERT INTO `category_cache` VALUES (366, 1, 'modelarstwo', 2895, '2026-01-13 13:55:18', '2026-01-13 13:55:18');
INSERT INTO `category_cache` VALUES (367, 1, 'sprzet rehabilitacyjny i ortopedyczny', 2896, '2026-01-13 13:55:19', '2026-01-13 13:55:19');
INSERT INTO `category_cache` VALUES (368, 1, 'mikrofony i słuchawki', 2897, '2026-01-13 13:55:20', '2026-01-13 13:55:20');
INSERT INTO `category_cache` VALUES (369, 1, 'urzadzenia sieciowe', 2898, '2026-01-13 13:55:21', '2026-01-13 13:55:21');
INSERT INTO `category_cache` VALUES (370, 1, 'hulajnogi elektryczne', 2899, '2026-01-13 13:55:22', '2026-01-13 13:55:22');
INSERT INTO `category_cache` VALUES (371, 1, 'krokomierze (pedometry)', 2900, '2026-01-13 13:55:23', '2026-01-13 13:55:23');
INSERT INTO `category_cache` VALUES (372, 1, 'obudowy i kadłubki', 2901, '2026-01-13 13:55:24', '2026-01-13 13:55:24');
INSERT INTO `category_cache` VALUES (373, 1, 'płyty głowne', 2902, '2026-01-13 13:55:25', '2026-01-13 13:55:25');
INSERT INTO `category_cache` VALUES (374, 1, 'wentylatory i radiatory', 2903, '2026-01-13 13:55:26', '2026-01-13 13:55:26');
INSERT INTO `category_cache` VALUES (375, 1, 'tasmy', 2904, '2026-01-13 13:55:27', '2026-01-13 13:55:27');
INSERT INTO `category_cache` VALUES (377, 1, 'karty minipci, minipcie', 2906, '2026-01-13 13:55:29', '2026-01-13 13:55:29');
INSERT INTO `category_cache` VALUES (378, 1, 'matryce i czesci', 2907, '2026-01-13 13:55:30', '2026-01-13 13:55:30');
INSERT INTO `category_cache` VALUES (379, 1, 'głosniki', 2908, '2026-01-13 13:55:31', '2026-01-13 13:55:31');
INSERT INTO `category_cache` VALUES (380, 1, 'napedy', 2909, '2026-01-13 13:55:32', '2026-01-13 13:55:32');
INSERT INTO `category_cache` VALUES (381, 1, 'klawiatury', 2910, '2026-01-13 13:55:33', '2026-01-13 13:55:33');
INSERT INTO `category_cache` VALUES (384, 1, 'płytki drukowane, moduły', 2913, '2026-01-13 13:55:36', '2026-01-13 13:55:36');
INSERT INTO `category_cache` VALUES (385, 1, 'gniazda zasilania', 2914, '2026-01-13 13:55:37', '2026-01-13 13:55:37');
INSERT INTO `category_cache` VALUES (386, 1, 'karty graficzne', 2915, '2026-01-13 13:55:38', '2026-01-13 13:55:38');
INSERT INTO `category_cache` VALUES (389, 1, 'czesci elektroniczne', 2918, '2026-01-13 13:55:41', '2026-01-13 13:55:41');
INSERT INTO `category_cache` VALUES (390, 1, 'aparatura pomiarowa', 2919, '2026-01-13 13:55:42', '2026-01-13 13:55:42');
INSERT INTO `category_cache` VALUES (393, 1, 'baterie i akumulatory rowerowe', 2922, '2026-01-13 13:55:45', '2026-01-13 13:55:45');
INSERT INTO `category_cache` VALUES (394, 1, 'pozostały sprzet medyczny', 2923, '2026-01-13 13:55:46', '2026-01-13 13:55:46');
INSERT INTO `category_cache` VALUES (395, 1, 'alternatywne zrodła energii', 2924, '2026-01-13 13:55:47', '2026-01-13 13:55:47');
INSERT INTO `category_cache` VALUES (396, 1, 'serwery', 2925, '2026-01-13 13:55:48', '2026-01-13 13:55:48');
INSERT INTO `category_cache` VALUES (397, 1, 'fotowoltaika', 2926, '2026-01-13 13:55:49', '2026-01-13 13:55:49');
INSERT INTO `category_cache` VALUES (398, 1, 'zasilanie', 2927, '2026-01-13 13:55:50', '2026-01-13 13:55:50');
INSERT INTO `category_cache` VALUES (400, 1, 'czesci zamienne', 2929, '2026-01-13 13:55:52', '2026-01-13 13:55:52');
INSERT INTO `category_cache` VALUES (401, 1, 'testery i interfejsy diagnostyczne', 2930, '2026-01-13 13:55:53', '2026-01-13 13:55:53');
INSERT INTO `category_cache` VALUES (402, 1, 'mikroskopy', 2931, '2026-01-13 13:55:54', '2026-01-13 13:55:54');
INSERT INTO `category_cache` VALUES (403, 1, 'radioodtwarzacze', 2932, '2026-01-13 13:55:56', '2026-01-13 13:55:56');
INSERT INTO `category_cache` VALUES (404, 1, 'pasy ciazowe', 2933, '2026-01-13 13:55:57', '2026-01-13 13:55:57');
INSERT INTO `category_cache` VALUES (405, 1, 'adaptery bluetooth', 2934, '2026-01-13 13:55:58', '2026-01-13 13:55:58');
INSERT INTO `category_cache` VALUES (406, 1, 'chłodzenie i tuning', 2935, '2026-01-13 13:55:59', '2026-01-13 13:55:59');
INSERT INTO `category_cache` VALUES (407, 1, 'mini kamery', 2936, '2026-01-13 13:56:00', '2026-01-13 13:56:00');
INSERT INTO `category_cache` VALUES (408, 1, 'baterie', 2937, '2026-01-13 13:56:01', '2026-01-13 13:56:01');
INSERT INTO `category_cache` VALUES (409, 1, 'zapałki i zapalniczki', 2938, '2026-01-13 13:56:02', '2026-01-13 13:56:02');
INSERT INTO `category_cache` VALUES (410, 1, 'podzespoły serwerowe', 2939, '2026-01-13 13:56:03', '2026-01-13 13:56:03');
INSERT INTO `category_cache` VALUES (411, 1, 'higiena i pielegnacja', 2940, '2026-01-13 13:56:04', '2026-01-13 13:56:04');
INSERT INTO `category_cache` VALUES (412, 1, 'kamery cofania', 2941, '2026-01-13 13:56:05', '2026-01-13 13:56:05');
INSERT INTO `category_cache` VALUES (413, 1, 'czujniki', 2942, '2026-01-13 13:56:06', '2026-01-13 13:56:06');
INSERT INTO `category_cache` VALUES (414, 1, 'rekawice', 2943, '2026-01-13 13:56:07', '2026-01-13 13:56:07');
INSERT INTO `category_cache` VALUES (415, 1, 'programatory', 2944, '2026-01-13 13:56:08', '2026-01-13 13:56:08');
INSERT INTO `category_cache` VALUES (416, 1, 'zestawy głosnomowiace', 2945, '2026-01-13 13:56:09', '2026-01-13 13:56:09');
INSERT INTO `category_cache` VALUES (417, 1, 'stabilizatory obrazu dla aparatow i kamer', 2946, '2026-01-13 13:56:10', '2026-01-13 13:56:10');
INSERT INTO `category_cache` VALUES (418, 1, 'zasilacze do laptopow', 2947, '2026-01-13 13:56:11', '2026-01-13 13:56:11');
INSERT INTO `category_cache` VALUES (419, 1, 'wtyczki', 2948, '2026-01-13 13:56:12', '2026-01-13 13:56:12');
INSERT INTO `category_cache` VALUES (420, 1, 'wypełniacze', 2949, '2026-01-13 13:56:13', '2026-01-13 13:56:13');
INSERT INTO `category_cache` VALUES (421, 1, 'kolektory słoneczne i panele fotowoltaiczne', 2950, '2026-01-13 13:56:14', '2026-01-13 13:56:14');
INSERT INTO `category_cache` VALUES (422, 1, 'spawarki inwertorowe', 2951, '2026-01-13 13:56:15', '2026-01-13 13:56:15');
INSERT INTO `category_cache` VALUES (423, 1, 'czesci serwisowe', 2952, '2026-01-13 13:56:16', '2026-01-13 13:56:16');
INSERT INTO `category_cache` VALUES (424, 1, 'karty pcmcia i expresscard', 2953, '2026-01-13 13:56:17', '2026-01-13 13:56:17');
INSERT INTO `category_cache` VALUES (425, 1, 'aspiratory i gruszki do nosa', 2954, '2026-01-13 13:56:18', '2026-01-13 13:56:18');
INSERT INTO `category_cache` VALUES (426, 1, 'przejsciowki, sledzie', 2955, '2026-01-13 13:56:19', '2026-01-13 13:56:19');
INSERT INTO `category_cache` VALUES (427, 1, 'pamiec ram', 2956, '2026-01-13 13:56:20', '2026-01-13 13:56:20');
INSERT INTO `category_cache` VALUES (428, 1, 'sprzet krotkofalarski', 2957, '2026-01-13 13:56:21', '2026-01-13 13:56:21');
INSERT INTO `category_cache` VALUES (429, 1, 'zdalnie sterowane', 2958, '2026-01-13 13:56:22', '2026-01-13 13:56:22');
INSERT INTO `category_cache` VALUES (430, 1, 'rehabilitacja i cwiczenia', 2959, '2026-01-13 13:56:23', '2026-01-13 13:56:23');
INSERT INTO `category_cache` VALUES (431, 1, 'wykrywacze podsłuchow', 2960, '2026-01-13 13:56:24', '2026-01-13 13:56:24');
INSERT INTO `category_cache` VALUES (432, 1, 'mikrofony', 2961, '2026-01-13 13:56:25', '2026-01-13 13:56:25');
INSERT INTO `category_cache` VALUES (433, 1, 'routery mobilne', 2962, '2026-01-13 13:56:26', '2026-01-13 13:56:26');
INSERT INTO `category_cache` VALUES (434, 1, 'obudowy', 2963, '2026-01-13 13:56:27', '2026-01-13 13:56:27');
INSERT INTO `category_cache` VALUES (435, 1, 'klapy i ramki', 2964, '2026-01-13 13:56:28', '2026-01-13 13:56:28');
INSERT INTO `category_cache` VALUES (436, 1, 'kieszenie i zaslepki', 2965, '2026-01-13 13:56:29', '2026-01-13 13:56:29');
INSERT INTO `category_cache` VALUES (437, 1, 'zawiasy', 2966, '2026-01-13 13:56:30', '2026-01-13 13:56:30');
INSERT INTO `category_cache` VALUES (438, 1, 'tasmy i inwertery', 2967, '2026-01-13 13:56:31', '2026-01-13 13:56:31');
INSERT INTO `category_cache` VALUES (439, 1, 'moduły', 2968, '2026-01-13 13:56:32', '2026-01-13 13:56:32');
INSERT INTO `category_cache` VALUES (440, 1, 'pozostałe', 2969, '2026-01-13 13:56:33', '2026-01-13 13:56:33');
INSERT INTO `category_cache` VALUES (441, 1, 'matryce', 2970, '2026-01-13 13:56:34', '2026-01-13 13:56:34');
INSERT INTO `category_cache` VALUES (442, 1, 'rezystory', 2971, '2026-01-13 13:56:35', '2026-01-13 13:56:35');
INSERT INTO `category_cache` VALUES (443, 1, 'oscyloskopy', 2972, '2026-01-13 13:56:36', '2026-01-13 13:56:36');
INSERT INTO `category_cache` VALUES (444, 1, 'kondensatory', 2973, '2026-01-13 13:56:37', '2026-01-13 13:56:37');
INSERT INTO `category_cache` VALUES (445, 1, 'zasilacze', 2974, '2026-01-13 13:56:38', '2026-01-13 13:56:38');
INSERT INTO `category_cache` VALUES (446, 1, 'multimetry', 2975, '2026-01-13 13:56:39', '2026-01-13 13:56:39');
INSERT INTO `category_cache` VALUES (447, 1, 'pasty i tasmy termoprzewodzace', 2976, '2026-01-13 13:56:40', '2026-01-13 13:56:40');
INSERT INTO `category_cache` VALUES (448, 1, 'procesory', 2977, '2026-01-13 13:56:41', '2026-01-13 13:56:41');
INSERT INTO `category_cache` VALUES (449, 1, 'depilatory', 2978, '2026-01-13 13:56:42', '2026-01-13 13:56:42');
INSERT INTO `category_cache` VALUES (450, 1, 'pirometry', 2979, '2026-01-13 13:56:43', '2026-01-13 13:56:43');
INSERT INTO `category_cache` VALUES (451, 1, 'przejsciowki', 2980, '2026-01-13 13:56:44', '2026-01-13 13:56:44');
INSERT INTO `category_cache` VALUES (452, 1, 'akcesoria i czesci', 2981, '2026-01-13 13:56:45', '2026-01-13 13:56:45');
INSERT INTO `category_cache` VALUES (453, 1, 'czesci i akcesoria', 2982, '2026-01-13 13:56:46', '2026-01-13 13:56:46');
INSERT INTO `category_cache` VALUES (454, 1, 'korektory postawy', 2983, '2026-01-13 13:56:48', '2026-01-13 13:56:48');
INSERT INTO `category_cache` VALUES (455, 1, 'tachometry', 2984, '2026-01-13 13:56:49', '2026-01-13 13:56:49');
INSERT INTO `category_cache` VALUES (456, 1, 'amperomierze', 2985, '2026-01-13 13:56:50', '2026-01-13 13:56:50');
INSERT INTO `category_cache` VALUES (457, 1, 'małej mocy (do 2w)', 2986, '2026-01-13 13:56:51', '2026-01-13 13:56:51');
INSERT INTO `category_cache` VALUES (458, 1, 'ceramiczne', 2987, '2026-01-13 13:56:52', '2026-01-13 13:56:52');
INSERT INTO `category_cache` VALUES (459, 1, 'duzej mocy (powyzej 2w)', 2988, '2026-01-13 13:56:53', '2026-01-13 13:56:53');
INSERT INTO `category_cache` VALUES (461, 1, 'moduły i płytki', 2990, '2026-01-13 13:56:55', '2026-01-13 13:56:55');
INSERT INTO `category_cache` VALUES (462, 1, 'ładowarki', 2991, '2026-01-13 13:56:56', '2026-01-13 13:56:56');
INSERT INTO `category_cache` VALUES (463, 1, 'laboratoryjne', 2992, '2026-01-13 13:56:57', '2026-01-13 13:56:57');

-- ----------------------------
-- Table structure for oauth_tokens
-- ----------------------------
DROP TABLE IF EXISTS `oauth_tokens`;
CREATE TABLE `oauth_tokens`  (
  `id` int UNSIGNED NOT NULL AUTO_INCREMENT,
  `app_user_id` int UNSIGNED NOT NULL,
  `access_token` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
  `refresh_token` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
  `expires_at` bigint NULL DEFAULT NULL,
  `allegro_user_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `client_access_token` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
  `client_token_expiry` bigint NULL DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `unique_user`(`app_user_id` ASC) USING BTREE,
  CONSTRAINT `oauth_tokens_ibfk_1` FOREIGN KEY (`app_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 6 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of oauth_tokens
-- ----------------------------
INSERT INTO `oauth_tokens` VALUES (1, 1, 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiI0ODE5NDI4NCIsInNjb3BlIjpbImFsbGVncm86YXBpOnNhbGU6b2ZmZXJzOnJlYWQiXSwiYWxsZWdyb19hcGkiOnRydWUsImlzcyI6Imh0dHBzOi8vYWxsZWdyby5wbCIsImV4cCI6MTc2ODM3MjUzMywianRpIjoiNmVkMzcyZjAtZTY4Zi00ZmQyLTkzYWYtYzFjNzQ3NzAwYTQ5IiwiY2xpZW50X2lkIjoiMzZjNDc2MzViYjFkNDk3N2I0OTQ3M2FkY2NiMzZkYTkifQ.dFlGvBE2o4Tg6ul96SQRAZyiDm_p0xtYi75kdLfRrYbFXcA5pbmp-IGVBBGGa8CfAlyf-LVNIzmjIRKbsr-tpxFeOModilYzLUuXcCHrOwVOYgTOyiDukg3jXnrAzSzPnGVvFh7YpnGVIF6weULBUsTNV0HL0nubLBnoTXLX3HvcJDUv7t1yt-2ETIaN0JHaLPfEFitf81ApKL_szUrFwRi32e8GkH-39ILXa1mGzIwPZEjNsdmOvD9FvmbtiCYr_BXkwYmCxmXE2nWF0Bq-yhxK7OGNYUu_Z028wh3tiUFvxNb6qI2wPvV8b0j7SPULeMfEcXQXboqu4MCcfavXgQ', 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX25hbWUiOiI0ODE5NDI4NCIsInNjb3BlIjpbImFsbGVncm86YXBpOnNhbGU6b2ZmZXJzOnJlYWQiXSwiYWxsZWdyb19hcGkiOnRydWUsImF0aSI6IjZlZDM3MmYwLWU2OGYtNGZkMi05M2FmLWMxYzc0NzcwMGE0OSIsImlzcyI6Imh0dHBzOi8vYWxsZWdyby5wbCIsImV4cCI6MTc3NjEwNTMzMywianRpIjoiNjY3ZTMxZWItNTVlYy00ZmQzLThkZjQtZjNkYjAyZDY5YmFhIiwiY2xpZW50X2lkIjoiMzZjNDc2MzViYjFkNDk3N2I0OTQ3M2FkY2NiMzZkYTkifQ.FgjHikYvqpzwp1tBPpTLnH2T0gZy8tE0o2YpSSqwY5dyaUJ2LoWMRtTnn5nK-gIvyCS_fLpisNCh1qNBS2GQ89ufk5j7P_Hc3Gj0W3nmrbuvf8Hp_iP5uEk2AQMYkzOuzlVlY5jfyegvv1GaULQ_lmSYEaNXyuO0gE8B4r2WK46H-Znjel2i8zy94Yc5QRJnuI75x9RInWG8TpADwL8c-cMW-9fqzBufZzwxSkKRTwZOkrQe2M0iWEFkpVm8neQ2FM9JxC-7C9mF94Bk4suAkUC2lj4Yn05rYoh-mBL-Cua5_tatuofmRLjzY_lk4Qz69VGRXwM8fqDNOiW5LFJTcA', 1768372472401, NULL, NULL, NULL, '2026-01-05 03:25:33', '2026-01-13 13:35:33');

-- ----------------------------
-- Table structure for prestashop_credentials
-- ----------------------------
DROP TABLE IF EXISTS `prestashop_credentials`;
CREATE TABLE `prestashop_credentials`  (
  `id` int UNSIGNED NOT NULL AUTO_INCREMENT,
  `app_user_id` int UNSIGNED NOT NULL,
  `base_url` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `api_key` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `unique_user`(`app_user_id` ASC) USING BTREE,
  CONSTRAINT `prestashop_credentials_ibfk_1` FOREIGN KEY (`app_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of prestashop_credentials
-- ----------------------------
INSERT INTO `prestashop_credentials` VALUES (1, 1, 'https://www.interkul.net', 'V2I5JNLHVMG5UVFLVQLSU3GCZ6VUB69V', '2026-01-04 02:02:47', '2026-01-04 02:02:47');

-- ----------------------------
-- Table structure for product_mappings
-- ----------------------------
DROP TABLE IF EXISTS `product_mappings`;
CREATE TABLE `product_mappings`  (
  `id` int UNSIGNED NOT NULL AUTO_INCREMENT,
  `app_user_id` int UNSIGNED NOT NULL,
  `allegro_offer_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `prestashop_product_id` int NOT NULL,
  `synced_at` datetime NULL DEFAULT NULL,
  `last_stock_sync` datetime NULL DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `unique_user_allegro_offer`(`app_user_id` ASC, `allegro_offer_id` ASC) USING BTREE,
  INDEX `idx_allegro_offer`(`allegro_offer_id` ASC) USING BTREE,
  INDEX `idx_prestashop_product`(`prestashop_product_id` ASC) USING BTREE,
  INDEX `idx_user_allegro`(`app_user_id` ASC, `allegro_offer_id` ASC) USING BTREE,
  CONSTRAINT `product_mappings_ibfk_1` FOREIGN KEY (`app_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 127 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of product_mappings
-- ----------------------------
INSERT INTO `product_mappings` VALUES (21, 1, '18157371059', 404, '2026-01-05 11:15:31', NULL, '2026-01-05 06:15:05', '2026-01-05 06:15:31');
INSERT INTO `product_mappings` VALUES (23, 1, '18157370994', 405, '2026-01-05 11:15:59', NULL, '2026-01-05 06:15:34', '2026-01-05 06:15:59');
INSERT INTO `product_mappings` VALUES (57, 1, '18085956980', 422, '2026-01-05 11:21:53', NULL, '2026-01-05 06:21:41', '2026-01-05 06:21:53');
INSERT INTO `product_mappings` VALUES (59, 1, '18085945278', 423, '2026-01-05 11:22:27', NULL, '2026-01-05 06:21:58', '2026-01-05 06:22:27');
INSERT INTO `product_mappings` VALUES (65, 1, '16647598601', 426, '2026-01-05 19:19:49', NULL, '2026-01-05 14:19:31', '2026-01-05 14:19:49');
INSERT INTO `product_mappings` VALUES (67, 1, '18235166779', 427, '2026-01-13 19:05:06', NULL, '2026-01-13 14:04:55', '2026-01-13 14:05:06');
INSERT INTO `product_mappings` VALUES (69, 1, '18232267873', 428, '2026-01-13 19:05:15', NULL, '2026-01-13 14:05:07', '2026-01-13 14:05:15');
INSERT INTO `product_mappings` VALUES (71, 1, '18226304450', 429, '2026-01-13 19:05:25', NULL, '2026-01-13 14:05:17', '2026-01-13 14:05:25');
INSERT INTO `product_mappings` VALUES (73, 1, '18222356123', 430, '2026-01-13 19:05:33', NULL, '2026-01-13 14:05:27', '2026-01-13 14:05:33');
INSERT INTO `product_mappings` VALUES (75, 1, '18210029911', 431, '2026-01-13 19:06:04', NULL, '2026-01-13 14:05:35', '2026-01-13 14:06:04');
INSERT INTO `product_mappings` VALUES (77, 1, '18210009757', 432, '2026-01-13 19:06:29', NULL, '2026-01-13 14:06:05', '2026-01-13 14:06:29');
INSERT INTO `product_mappings` VALUES (79, 1, '18206861918', 433, '2026-01-13 19:06:34', NULL, '2026-01-13 14:06:31', '2026-01-13 14:06:34');
INSERT INTO `product_mappings` VALUES (81, 1, '18179757205', 434, '2026-01-13 19:06:42', NULL, '2026-01-13 14:06:36', '2026-01-13 14:06:42');
INSERT INTO `product_mappings` VALUES (83, 1, '18164347774', 435, '2026-01-13 19:07:12', NULL, '2026-01-13 14:06:44', '2026-01-13 14:07:12');
INSERT INTO `product_mappings` VALUES (85, 1, '18164344911', 436, '2026-01-13 19:07:42', NULL, '2026-01-13 14:07:14', '2026-01-13 14:07:42');
INSERT INTO `product_mappings` VALUES (87, 1, '18164341038', 437, '2026-01-13 19:08:13', NULL, '2026-01-13 14:07:44', '2026-01-13 14:08:13');
INSERT INTO `product_mappings` VALUES (89, 1, '18164328251', 438, '2026-01-13 19:08:42', NULL, '2026-01-13 14:08:15', '2026-01-13 14:08:42');
INSERT INTO `product_mappings` VALUES (91, 1, '18157371809', 439, '2026-01-13 19:09:06', NULL, '2026-01-13 14:08:44', '2026-01-13 14:09:06');
INSERT INTO `product_mappings` VALUES (93, 1, '18157371668', 440, '2026-01-13 19:09:30', NULL, '2026-01-13 14:09:08', '2026-01-13 14:09:30');
INSERT INTO `product_mappings` VALUES (95, 1, '18149631313', 441, '2026-01-13 19:09:38', NULL, '2026-01-13 14:09:32', '2026-01-13 14:09:38');
INSERT INTO `product_mappings` VALUES (97, 1, '18149558988', 442, '2026-01-13 19:09:58', NULL, '2026-01-13 14:09:40', '2026-01-13 14:09:58');
INSERT INTO `product_mappings` VALUES (99, 1, '18149540807', 443, '2026-01-13 19:10:20', NULL, '2026-01-13 14:10:00', '2026-01-13 14:10:20');
INSERT INTO `product_mappings` VALUES (101, 1, '18149522792', 444, '2026-01-13 19:10:41', NULL, '2026-01-13 14:10:22', '2026-01-13 14:10:41');
INSERT INTO `product_mappings` VALUES (103, 1, '18149497152', 445, '2026-01-13 19:10:48', NULL, '2026-01-13 14:10:42', '2026-01-13 14:10:48');
INSERT INTO `product_mappings` VALUES (105, 1, '18132925360', 446, '2026-01-13 19:10:57', NULL, '2026-01-13 14:10:50', '2026-01-13 14:10:57');
INSERT INTO `product_mappings` VALUES (107, 1, '18132919074', 447, '2026-01-13 19:11:05', NULL, '2026-01-13 14:10:58', '2026-01-13 14:11:05');
INSERT INTO `product_mappings` VALUES (109, 1, '18121547121', 448, '2026-01-13 19:11:18', NULL, '2026-01-13 14:11:07', '2026-01-13 14:11:18');
INSERT INTO `product_mappings` VALUES (111, 1, '18115751976', 449, '2026-01-13 19:11:41', NULL, '2026-01-13 14:11:19', '2026-01-13 14:11:41');
INSERT INTO `product_mappings` VALUES (113, 1, '18115748148', 450, '2026-01-13 19:12:10', NULL, '2026-01-13 14:11:43', '2026-01-13 14:12:10');
INSERT INTO `product_mappings` VALUES (115, 1, '18115745472', 451, '2026-01-13 19:12:34', NULL, '2026-01-13 14:12:12', '2026-01-13 14:12:34');
INSERT INTO `product_mappings` VALUES (117, 1, '18115732047', 452, '2026-01-13 19:12:59', NULL, '2026-01-13 14:12:36', '2026-01-13 14:12:59');
INSERT INTO `product_mappings` VALUES (119, 1, '18097804305', 453, '2026-01-13 19:13:06', NULL, '2026-01-13 14:13:00', '2026-01-13 14:13:06');
INSERT INTO `product_mappings` VALUES (121, 1, '18097792811', 454, '2026-01-13 19:13:17', NULL, '2026-01-13 14:13:08', '2026-01-13 14:13:17');
INSERT INTO `product_mappings` VALUES (123, 1, '18085993171', 455, '2026-01-13 19:13:26', NULL, '2026-01-13 14:13:19', '2026-01-13 14:13:26');
INSERT INTO `product_mappings` VALUES (125, 1, '18085985710', 456, '2026-01-13 19:13:35', NULL, '2026-01-13 14:13:28', '2026-01-13 14:13:35');

-- ----------------------------
-- Table structure for sync_logs
-- ----------------------------
DROP TABLE IF EXISTS `sync_logs`;
CREATE TABLE `sync_logs`  (
  `id` int UNSIGNED NOT NULL AUTO_INCREMENT,
  `app_user_id` int UNSIGNED NOT NULL,
  `status` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `message` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `product_name` varchar(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `offer_id` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `prestashop_product_id` int NULL DEFAULT NULL,
  `stock_change_from` int NULL DEFAULT NULL,
  `stock_change_to` int NULL DEFAULT NULL,
  `allegro_price` decimal(10, 2) NULL DEFAULT NULL,
  `prestashop_price` decimal(10, 2) NULL DEFAULT NULL,
  `category_name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL DEFAULT NULL,
  `timestamp` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`) USING BTREE,
  INDEX `idx_user_timestamp`(`app_user_id` ASC, `timestamp` ASC) USING BTREE,
  INDEX `idx_user_status`(`app_user_id` ASC, `status` ASC) USING BTREE,
  CONSTRAINT `sync_logs_ibfk_1` FOREIGN KEY (`app_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 11749 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of sync_logs
-- ----------------------------
INSERT INTO `sync_logs` VALUES (11718, 1, 'info', 'Starting stock sync: Found 30 products in PrestaShop. Checking stock for each product...', NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, '2026-01-14 04:57:18');
INSERT INTO `sync_logs` VALUES (11719, 1, 'unchanged', 'Stock unchanged: Allegro=7, PrestaShop=7 (already in sync)', 'Interfejs Diagnostyczny Samochodowy OBD2 Bt Pro adapter', '18235166779', 427, 7, 7, 299.00, 299.00, 'Testery i interfejsy diagnostyczne', '2026-01-14 04:57:20');
INSERT INTO `sync_logs` VALUES (11720, 1, 'unchanged', 'Stock unchanged: Allegro=0, PrestaShop=0 (already in sync)', 'Lenovo Thinkpad L520 i5 16GB 480GB SSD bateria zasilacz warsztatowy', '18164344911', 436, 0, 0, 549.00, 549.00, 'Laptopy', '2026-01-14 04:57:20');
INSERT INTO `sync_logs` VALUES (11721, 1, 'unchanged', 'Stock unchanged: Allegro=0, PrestaShop=0 (already in sync)', 'Lenovo Thinkpad L520 i5 16GB 1TB SSD bateria zasilacz warsztatowy', '18164347774', 435, 0, 0, 649.00, 649.00, 'Laptopy', '2026-01-14 04:57:20');
INSERT INTO `sync_logs` VALUES (11722, 1, 'unchanged', 'Stock unchanged: Allegro=1, PrestaShop=1 (already in sync)', 'Lenovo Thinkpad L520 i5 8GB 480GB SSD bateria zasilacz warsztatowy', '18164341038', 437, 1, 1, 469.00, 469.00, 'Laptopy', '2026-01-14 04:57:20');
INSERT INTO `sync_logs` VALUES (11723, 1, 'unchanged', 'Stock unchanged: Allegro=6, PrestaShop=6 (already in sync)', 'Interfejs Diagnostyczny Samochodowy OBD2 Bt Pro adapter', '18232267873', 428, 6, 6, 299.00, 299.00, 'Testery i interfejsy diagnostyczne', '2026-01-14 04:57:20');
INSERT INTO `sync_logs` VALUES (11724, 1, 'unchanged', 'Stock unchanged: Allegro=39, PrestaShop=39 (already in sync)', 'Gumka TrackPointa klawiatury laptopów Dell HP kwadrat 4.5x4.5mm czarna', '18222356123', 430, 39, 39, 5.00, 5.00, 'Klawiatury', '2026-01-14 04:57:20');
INSERT INTO `sync_logs` VALUES (11725, 1, 'unchanged', 'Stock unchanged: Allegro=0, PrestaShop=0 (already in sync)', 'ADAPTER Przedłużaka z dysku M.2 NVMe SSD 2230 2242 2260 na 2280', '18132925360', 446, 0, 0, 9.00, 9.00, 'Przejściówki', '2026-01-14 04:57:20');
INSERT INTO `sync_logs` VALUES (11726, 1, 'unchanged', 'Stock unchanged: Allegro=1, PrestaShop=1 (already in sync)', 'HP Zbook 15 G6 Workstation 15.6 16GB 500GB Quadro T1000 gamingowy bateria', '18157371809', 439, 1, 1, 1499.00, 1499.00, 'Laptopy', '2026-01-14 04:57:20');
INSERT INTO `sync_logs` VALUES (11727, 1, 'unchanged', 'Stock unchanged: Allegro=3, PrestaShop=3 (already in sync)', 'Podgrzewacz do Butelek i Napojów z 3-stopniową Regulacją Temperatury USB 5V', '18149497152', 445, 3, 3, 54.00, 54.00, 'Podgrzewacze', '2026-01-14 04:57:20');
INSERT INTO `sync_logs` VALUES (11728, 1, 'unchanged', 'Stock unchanged: Allegro=7, PrestaShop=7 (already in sync)', 'Interfejs Diagnostyczny Samochodowy OBD2 Bt Pro adapter', '18226304450', 429, 7, 7, 299.00, 299.00, 'Testery i interfejsy diagnostyczne', '2026-01-14 04:57:20');
INSERT INTO `sync_logs` VALUES (11729, 1, 'unchanged', 'Stock unchanged: Allegro=2, PrestaShop=2 (already in sync)', 'Pas ciążowy Lizhoup beżowy uniwersalny bawełniany zapięcie rzepy rozm. L', '18149522792', 444, 2, 2, 69.00, 69.00, 'Pasy ciążowe', '2026-01-14 04:57:20');
INSERT INTO `sync_logs` VALUES (11730, 1, 'unchanged', 'Stock unchanged: Allegro=1, PrestaShop=1 (already in sync)', 'Dell Precision M6800 17.3 16GB 500GB SSD nVidia Quadro M4000M gamingowy bat', '18210029911', 431, 1, 1, 1099.00, 1099.00, 'Laptopy', '2026-01-14 04:57:20');
INSERT INTO `sync_logs` VALUES (11731, 1, 'unchanged', 'Stock unchanged: Allegro=1, PrestaShop=1 (already in sync)', 'Dell Precision M6800 17.3 16GB 1TB SSD nVidia Quadro M4000M gamingowy bat.', '18210009757', 432, 1, 1, 1199.00, 1199.00, 'Laptopy', '2026-01-14 04:57:20');
INSERT INTO `sync_logs` VALUES (11732, 1, 'unchanged', 'Stock unchanged: Allegro=0, PrestaShop=0 (already in sync)', 'Aspirator do nosa elektryczny dla niemowląt cichy 3 końcówki muzyka 9 poz.', '18149631313', 441, 0, 0, 135.00, 135.00, 'Aspiratory i gruszki do nosa', '2026-01-14 04:57:20');
INSERT INTO `sync_logs` VALUES (11733, 1, 'unchanged', 'Stock unchanged: Allegro=9, PrestaShop=9 (already in sync)', 'Webhosting1st - polski hosting stron www - od 2018 roku - od 35zł rocznie', '18206861918', 433, 9, 9, 35.00, 35.00, 'Internet', '2026-01-14 04:57:21');
INSERT INTO `sync_logs` VALUES (11734, 1, 'unchanged', 'Stock unchanged: Allegro=1, PrestaShop=1 (already in sync)', 'Lenovo Thinkpad L520 i5 8GB 120GB SSD bateria zasilacz warsztatowy', '18164328251', 438, 1, 1, 369.00, 369.00, 'Laptopy', '2026-01-14 04:57:21');
INSERT INTO `sync_logs` VALUES (11735, 1, 'unchanged', 'Stock unchanged: Allegro=3, PrestaShop=3 (already in sync)', 'Bezprzewodowy adapter Carplay Box 5.0 (2Air) Bezprzewodowy / Android Auto', '18149540807', 443, 3, 3, 75.00, 75.00, 'Radioodtwarzacze', '2026-01-14 04:57:21');
INSERT INTO `sync_logs` VALUES (11736, 1, 'unchanged', 'Stock unchanged: Allegro=1, PrestaShop=1 (already in sync)', 'HP Zbook 15 G6 Workstation 15.6 16GB 1TB SSD Quadro T1000 gamingowy bateria', '18157371668', 440, 1, 1, 1599.00, 1599.00, 'Laptopy', '2026-01-14 04:57:21');
INSERT INTO `sync_logs` VALUES (11737, 1, 'unchanged', 'Stock unchanged: Allegro=3, PrestaShop=3 (already in sync)', 'Mikroskop cyfrowy Zosudull 1200x 12 MP 7\'\' HD z pilotem i oświetleniem LED', '18149558988', 442, 3, 3, 319.00, 319.00, 'Mikroskopy', '2026-01-14 04:57:21');
INSERT INTO `sync_logs` VALUES (11738, 1, 'unchanged', 'Stock unchanged: Allegro=2, PrestaShop=2 (already in sync)', 'Wzmacniacz audio 2SC5200 2SA1943 300W Mono DC +-20-90V klasa AB 8OHM', '18179757205', 434, 2, 2, 99.00, 99.00, 'Moduły', '2026-01-14 04:57:21');
INSERT INTO `sync_logs` VALUES (11739, 1, 'unchanged', 'Stock unchanged: Allegro=1, PrestaShop=1 (already in sync)', 'Lenovo V14-IIL 14.0\" i5-1035G1 12GB 1TB SSD bateria zasilacz', '18115732047', 452, 1, 1, 869.00, 869.00, 'Laptopy', '2026-01-14 04:57:23');
INSERT INTO `sync_logs` VALUES (11740, 1, 'unchanged', 'Stock unchanged: Allegro=1, PrestaShop=1 (already in sync)', 'Lenovo V14-IIL 14.0\" i5-1035G1 20GB 500GB SSD bateria zasilacz', '18115748148', 450, 1, 1, 909.00, 909.00, 'Laptopy', '2026-01-14 04:57:23');
INSERT INTO `sync_logs` VALUES (11741, 1, 'unchanged', 'Stock unchanged: Allegro=1, PrestaShop=1 (already in sync)', 'Lenovo V14-IIL 14.0\" i5-1035G1 20GB 1TB SSD bateria zasilacz', '18115745472', 451, 1, 1, 989.00, 989.00, 'Laptopy', '2026-01-14 04:57:23');
INSERT INTO `sync_logs` VALUES (11742, 1, 'unchanged', 'Stock unchanged: Allegro=11, PrestaShop=11 (already in sync)', 'Pamięci RAM Hynix DDR2 PC2-6400S 2x2GB (4GB) 800Mhz', '18097804305', 453, 11, 11, 89.00, 89.00, 'Pamięć RAM', '2026-01-14 04:57:23');
INSERT INTO `sync_logs` VALUES (11743, 1, 'unchanged', 'Stock unchanged: Allegro=3, PrestaShop=3 (already in sync)', 'Multimetr miernik z cyfrowym oscyloskopem 3w1 ZOYI ZT-703S 3,5\'\' 50Mhz', '18121547121', 448, 3, 3, 419.00, 419.00, 'Multimetry', '2026-01-14 04:57:23');
INSERT INTO `sync_logs` VALUES (11744, 1, 'unchanged', 'Stock unchanged: Allegro=86, PrestaShop=86 (already in sync)', 'Gumka TrackPointa klawiatury laptopów Dell HP kwadrat 3.5x3.5mm czarna', '18132919074', 447, 86, 86, 5.00, 5.00, 'Klawiatury', '2026-01-14 04:57:23');
INSERT INTO `sync_logs` VALUES (11745, 1, 'unchanged', 'Stock unchanged: Allegro=1, PrestaShop=1 (already in sync)', 'Lenovo V14-IIL 14.0\" i5-1035G1 12GB 500GB SSD bateria zasilacz', '18115751976', 449, 1, 1, 789.00, 789.00, 'Laptopy', '2026-01-14 04:57:23');
INSERT INTO `sync_logs` VALUES (11746, 1, 'unchanged', 'Stock unchanged: Allegro=12, PrestaShop=12 (already in sync)', 'Pamięci RAM Hynix PC2-6400S DDR2 2GB 800Mhz', '18097792811', 454, 12, 12, 49.00, 49.00, 'Pamięć RAM', '2026-01-14 04:57:23');
INSERT INTO `sync_logs` VALUES (11747, 1, 'unchanged', 'Stock unchanged: Allegro=1, PrestaShop=1 (already in sync)', 'Zestaw rezystorów dużej mocy 3W 5% 300szt 60 wartości 0 - 820k Ohm', '18085985710', 456, 1, 1, 149.00, 149.00, 'Dużej mocy (powyżej 2W)', '2026-01-14 04:57:23');
INSERT INTO `sync_logs` VALUES (11748, 1, 'unchanged', 'Stock unchanged: Allegro=1, PrestaShop=1 (already in sync)', 'Zestaw rezystorów dużej mocy 5W 5% 300szt 60 wartości 0 - 820k Ohm', '18085993171', 455, 1, 1, 199.00, 199.00, 'Dużej mocy (powyżej 2W)', '2026-01-14 04:57:23');

-- ----------------------------
-- Table structure for user_sync_settings
-- ----------------------------
DROP TABLE IF EXISTS `user_sync_settings`;
CREATE TABLE `user_sync_settings`  (
  `id` int UNSIGNED NOT NULL AUTO_INCREMENT,
  `app_user_id` int UNSIGNED NOT NULL,
  `auto_sync_enabled` tinyint(1) NOT NULL DEFAULT 0,
  `sync_interval_ms` int UNSIGNED NOT NULL DEFAULT 300000,
  `last_sync_time` datetime NULL DEFAULT NULL,
  `next_sync_time` datetime NULL DEFAULT NULL,
  `sync_timer_active` tinyint(1) NOT NULL DEFAULT 0,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `unique_user`(`app_user_id` ASC) USING BTREE,
  CONSTRAINT `user_sync_settings_ibfk_1` FOREIGN KEY (`app_user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE = InnoDB AUTO_INCREMENT = 740 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of user_sync_settings
-- ----------------------------
INSERT INTO `user_sync_settings` VALUES (1, 1, 1, 180000, '2026-01-14 04:57:17', '2026-01-14 05:03:17', 1, '2026-01-05 03:36:00', '2026-01-14 00:00:17');

-- ----------------------------
-- Table structure for users
-- ----------------------------
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users`  (
  `id` int UNSIGNED NOT NULL AUTO_INCREMENT,
  `email` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `password_hash` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `password_salt` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `role` enum('admin','user') CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'user',
  `failed_attempts` int UNSIGNED NOT NULL DEFAULT 0,
  `lock_until` datetime NULL DEFAULT NULL,
  `is_active` tinyint(1) NOT NULL DEFAULT 1,
  `last_login_at` datetime NULL DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`) USING BTREE,
  UNIQUE INDEX `email`(`email` ASC) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 2 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_unicode_ci ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of users
-- ----------------------------
INSERT INTO `users` VALUES (1, 'admin@gmail.com', '1a9c6d9792207a66a141e77b98a554c49afc7d480058fdd2369689aac295cce4dd8913bb39edfbdf6d1524cdc0b6c14a8f7a574a22e575ee857f64ba41a83c3e', '2b2ed206a88c4aa1a3edfdcc1a3ab61c', 'admin', 0, NULL, 1, '2026-01-13 13:35:31', '2026-01-04 02:01:24', '2026-01-13 13:35:31');

SET FOREIGN_KEY_CHECKS = 1;
