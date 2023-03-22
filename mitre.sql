-- phpMyAdmin SQL Dump
-- version 5.2.0
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Mar 22, 2023 at 06:58 AM
-- Server version: 10.4.27-MariaDB
-- PHP Version: 8.2.0

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `mitre`
--

-- --------------------------------------------------------

--
-- Table structure for table `accounts`
--

CREATE TABLE `accounts` (
  `id` int(11) NOT NULL,
  `username` varchar(50) DEFAULT NULL,
  `password` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `accounts`
--

INSERT INTO `accounts` (`id`, `username`, `password`) VALUES
(1, 'venkat', '1234');

-- --------------------------------------------------------

--
-- Table structure for table `admin`
--

CREATE TABLE `admin` (
  `id` int(11) NOT NULL,
  `username` varchar(50) DEFAULT NULL,
  `password` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `admin`
--

INSERT INTO `admin` (`id`, `username`, `password`) VALUES
(1, 'venkat', '123456');

-- --------------------------------------------------------

--
-- Table structure for table `categories`
--

CREATE TABLE `categories` (
  `id` int(11) NOT NULL,
  `tactics` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `categories`
--

INSERT INTO `categories` (`id`, `tactics`) VALUES
(1, 'Reconnaissance'),
(2, 'Resource Development'),
(3, 'Initial Access'),
(4, 'Execution'),
(5, 'Persistence'),
(6, 'Privilege Escalation'),
(7, 'Defense Evasion'),
(8, 'Credential Access'),
(9, 'Discovery'),
(10, 'Lateral Movement'),
(11, 'Collection'),
(12, 'Command and Control'),
(13, 'Exfiltration'),
(14, 'Impact');

-- --------------------------------------------------------

--
-- Table structure for table `companies`
--

CREATE TABLE `companies` (
  `id` int(11) NOT NULL,
  `tenants` varchar(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `companies`
--

INSERT INTO `companies` (`id`, `tenants`) VALUES
(1, 'Aurobindo'),
(2, 'ABP'),
(3, 'DLPL'),
(4, 'AZB');

-- --------------------------------------------------------

--
-- Table structure for table `subcategories`
--

CREATE TABLE `subcategories` (
  `id` int(11) NOT NULL,
  `name` longtext DEFAULT NULL,
  `category_id` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `subcategories`
--

INSERT INTO `subcategories` (`id`, `name`, `category_id`) VALUES
(1, 'active scanning', 1),
(2, 'gather victim host information', 1),
(3, 'gather victim identity information', 1),
(4, 'gather victim network information', 1),
(5, 'gather victim org information', 1),
(6, 'phishing for information', 1),
(7, 'search closed sources', 1),
(8, 'search open technical databses', 1),
(9, 'search open websites/domains', 1),
(10, 'search victim-owned websites', 1),
(11, 'acquire infrastructure', 2),
(12, 'compromise accounts', 2),
(13, 'compromise infrasructure', 2),
(14, 'develop capabilities', 2),
(15, 'establish accounts', 2),
(16, 'obtain capabilities', 2),
(17, 'stage capabilities', 2),
(18, 'drive by compromise', 3),
(19, 'exploit public facing application', 3),
(20, 'external remote services', 3),
(21, 'hardware additions', 3),
(22, 'phishing for information', 3),
(23, 'replication through removable media', 3),
(24, 'supply chain compromise', 3),
(25, 'trusted relationship', 3),
(26, 'valid accounts', 3),
(27, 'command and scripting interpreter', 4),
(28, 'container administration command', 4),
(29, 'deploy container', 4),
(30, 'exploitation for client execution', 4),
(31, 'inter-process communication', 4),
(32, 'native API', 4),
(33, 'scheduled task/job', 4),
(34, 'serverless execution', 4),
(35, 'shared modules', 4),
(36, 'software deployment tools', 4),
(37, 'system services', 4),
(38, 'user execution', 4),
(39, 'windows management instrumentation', 4),
(40, 'Account manipulation', 5),
(41, 'BITS Jobs', 5),
(42, 'Boot or Logon Autostart Execution', 5),
(43, 'Boot or Logon Initialization Scripts', 5),
(44, 'Browser Extension', 5),
(45, 'Compromise Client Software Binary', 5),
(46, 'Create account', 5),
(47, 'Create or modify system process', 5),
(48, 'Event triggered Execution', 5),
(49, 'External remote services', 5),
(50, 'Hijack Execution Flow', 5),
(51, 'Implant internal Image', 5),
(52, 'Modify Authentication process', 5),
(53, 'Office application startup', 5),
(54, 'Pre OS boot', 5),
(55, 'Schedule Task/Job', 5),
(56, 'Server Software Component', 5),
(57, 'Traffic signalling', 5),
(58, 'Valid accounts', 5),
(59, 'Abuse Elevation Control Mechanism ', 6),
(60, 'Access Token Manipulation ', 6),
(61, 'Boot or Logon Autostart Execution ', 6),
(62, 'Boot or Logon Initialization Scripts ', 6),
(63, 'Create or Modify System Process ', 6),
(64, 'Domain Policy Modification ', 6),
(65, 'Escape to Host', 6),
(66, 'Event Triggered Execution ', 6),
(67, 'Exploitation for Privilege Escalation', 6),
(68, 'Hijack Execution Flow ', 6),
(69, 'Process Injection ', 6),
(70, 'Scheduled Task/Job ', 6),
(71, 'Valid Accounts ', 6),
(72, 'Abuse Elevation Control Mechanism ', 7),
(73, 'Access Token Manipulation ', 7),
(74, 'BITS Jobs', 7),
(75, 'Build Image on Host', 7),
(76, 'Debugger Evasion', 7),
(77, 'Deobfuscate/Decode Files or Information', 7),
(78, 'Deploy Container', 7),
(79, 'Direct Volume Access', 7),
(80, 'Domain Policy Modification ', 7),
(81, 'Execution Guardrails ', 7),
(82, 'Exploitation for Defense Evasion', 7),
(83, 'File and Directory Permissions Modification ', 7),
(84, 'Hide Artifacts ', 7),
(85, 'Hijack Execution Flow ', 7),
(86, 'Impair Defenses ', 7),
(87, 'Indicator Removal ', 7),
(88, 'Indirect Command Execution', 7),
(89, 'Masquerading ', 7),
(90, 'Modify Authentication Process ', 7),
(91, 'Modify Cloud Compute Infrastructure ', 7),
(92, 'Modify Registry', 7),
(93, 'Modify System Image ', 7),
(94, 'Network Boundary Bridging ', 7),
(95, 'Obfuscated Files or Information ', 7),
(96, 'Plist File Modification', 7),
(97, 'Pre-OS Boot ', 7),
(98, 'Process Injection ', 7),
(99, 'Reflective Code Loading', 7),
(100, 'Rogue Domain Controller', 7),
(101, 'Rootkit', 7),
(102, 'Subvert Trust Controls ', 7),
(103, 'System Binary Proxy Execution ', 7),
(104, 'System Binary Proxy Execution ', 7),
(105, 'System Script Proxy Execution ', 7),
(106, 'Template Injection', 7),
(107, 'Traffic Signaling ', 7),
(108, 'Trusted Developer Utilities Proxy Execution (1)', 7),
(109, 'Unused/Unsupported Cloud Regions', 7),
(110, 'Use Alternate Authentication Material ', 7),
(111, 'Valid Accounts ', 7),
(112, 'Virtualization/Sandbox Evasion ', 7),
(113, 'Weaken Encryption ', 7),
(114, 'XSL Script Processing', 7),
(115, 'Adversary-in-the-Middle', 8),
(116, 'Brute Force', 8),
(117, 'Credentials from Password Stores', 8),
(118, 'Exploitation for Credential Access', 8),
(119, 'Forced Authentication', 8),
(120, 'Forge Web Credentials', 8),
(121, 'Input Capture', 8),
(122, 'Modify Authentication Process', 8),
(123, 'Multi-Factor Authentication Interception', 8),
(124, 'Multi-Factor Authentication Request Generation', 8),
(125, 'Network Sniffing', 8),
(126, 'OS Credential Dumping', 8),
(127, 'Steal Application Access Token', 8),
(128, 'Steal or Forge Authentication Certificates', 8),
(129, 'Steal or Forge Kerberos Tickets', 8),
(130, 'Steal Web Session Cookie', 8),
(131, 'Unsecured Credentials', 8),
(132, 'Account Discovery', 9),
(133, 'Application Window Discovery', 9),
(134, 'Browser Bookmark Discovery', 9),
(135, 'Cloud Infrastructure Discovery', 9),
(136, 'Cloud Service Dashboard', 9),
(137, 'Cloud Service Discovery', 9),
(138, 'Cloud Storage Object Discovery', 9),
(139, 'Container and Resource Discovery', 9),
(140, 'Debugger Evasion', 9),
(141, 'T1622', 9),
(142, 'Domain Trust Discovery', 9),
(143, 'File and Directory Discovery', 9),
(144, 'Group Policy Discovery', 9),
(145, 'Network Service Discovery', 9),
(146, 'Network Share Discovery', 9),
(147, 'Network Sniffing', 9),
(148, 'Password Policy Discovery', 9),
(149, 'Peripheral Device Discovery', 9),
(150, 'Permission Groups Discovery', 9),
(151, 'Process Discovery', 9),
(152, 'Query Registry', 9),
(153, 'Remote System Discovery', 9),
(154, 'Software Discovery', 9),
(155, 'System Information Discovery', 9),
(156, 'System Location Discovery', 9),
(157, 'System Network Configuration Discovery', 9),
(158, 'System Network Connections Discovery', 9),
(159, 'System Owner/User Discovery', 9),
(160, 'System Service Discovery', 9),
(161, 'System Time Discovery', 9),
(162, 'Virtualization/Sandbox Evasion', 9),
(163, 'Exploitation of Remote Services', 10),
(164, 'Internal Spearphishing', 10),
(165, 'Lateral Tool Transfer', 10),
(166, 'Remote Service Session Hijacking', 10),
(167, 'Remote Services', 10),
(168, 'Replication Through Removable Media', 10),
(169, 'Software Deployment Tools', 10),
(170, 'Taint Shared Content', 10),
(171, 'Use Alternate Authentication Material', 10),
(172, 'Adversary-in-the-Middle', 11),
(173, 'Archive Collected Data', 11),
(174, 'Audio Capture', 11),
(175, 'Automated Collection', 11),
(176, 'Browser Session Hijacking', 11),
(177, 'Clipboard Data', 11),
(178, 'Data from Cloud Storage', 11),
(179, 'Data from Configuration Repository', 11),
(180, 'Data from Information Repositories', 11),
(181, 'Data from Local System', 11),
(182, 'Data from Network Shared Drive', 11),
(183, 'Data from Removable Media', 11),
(184, 'Data Staged', 11),
(185, 'Email Collection', 11),
(186, 'Input Capture', 11),
(187, 'Screen Capture', 11),
(188, 'Video Capture', 11),
(189, 'Application Layer Protocol', 12),
(190, 'Communication Through Removable Media', 12),
(191, 'Data Encoding', 12),
(192, 'Data Obfuscation', 12),
(193, 'Dynamic Resolution', 12),
(194, 'Encrypted Channel', 12),
(195, 'Fallback Channels', 12),
(196, 'Ingress Tool Transfer', 12),
(197, 'Multi-Stage Channels', 12),
(198, 'Non-Application Layer Protocol', 12),
(199, 'Non-Standard Port', 12),
(200, 'Protocol Tunneling', 12),
(201, 'Proxy', 12),
(202, 'Remote Access Software', 12),
(203, 'Traffic Signaling', 12),
(204, 'Web Service', 12),
(205, 'Automated Exfiltration', 13),
(206, 'Data Transfer Size Limits', 13),
(207, 'Exfiltration Over Alternative Protocol', 13),
(208, 'Exfiltration Over C2 Channel', 13),
(209, 'Exfiltration Over Other Network Medium', 13),
(210, 'Exfiltration Over Physical Medium', 13),
(211, 'Exfiltration Over Web Service', 13),
(212, 'Scheduled Transfer', 13),
(213, 'Transfer Data to Cloud Account', 13),
(214, 'Data Destruction', 14),
(215, 'Data Encrypted for Impact', 14),
(216, 'Data Manipulation', 14),
(217, 'Defacement', 14),
(218, 'Disk Wipe', 14),
(219, 'Endpoint Denial of Service', 14),
(220, 'Firmware Corruption', 14),
(221, 'Inhibit System Recovery', 14),
(222, 'Network Denial of Service', 14),
(223, 'Resource Hijacking', 14),
(224, 'Service Stop', 14),
(225, 'System Shutdown/Reboot', 14),
(226, 'Account Access Removal', 14);

-- --------------------------------------------------------

--
-- Table structure for table `usecases`
--

CREATE TABLE `usecases` (
  `id` int(11) NOT NULL,
  `usecases` longtext DEFAULT NULL,
  `subcategory_id` int(11) DEFAULT NULL,
  `category_id` int(11) DEFAULT NULL,
  `company_id` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Dumping data for table `usecases`
--

INSERT INTO `usecases` (`id`, `usecases`, `subcategory_id`, `category_id`, `company_id`) VALUES
(1, 'PowerShell Remote Access', 27, 4, 1),
(2, 'Malware on Disk', 19, 3, 1),
(3, 'Bad Source Reputation Anomaly', 38, 4, 1),
(4, 'Uncommon Process Anomaly', 36, 4, 1),
(5, 'Bad Destination Reputation Anomaly', 38, 4, 1),
(6, 'Abnormal Parent / Child Process', 60, 6, 1),
(7, 'Process Anomaly', 64, 6, 1),
(8, 'Short Lived Windows Accounts', 27, 3, 1),
(9, 'Audit Log Cleared', 88, 7, 1),
(10, 'SEPM Infection - Left Alone', NULL, 9, 1),
(11, 'User added to security group', 41, 5, 1),
(12, 'Windows System Shutdown or Restart', 225, 14, 1),
(13, 'Software uninstalled on the device', 88, 7, 1),
(14, 'Software uninstalled on the device', 87, 7, 1),
(15, 'Checkpoint Firewall - Low severity IPS Detections', NULL, 9, 1),
(16, 'Checkpoint Firewall - Medium severity IPS Detections', NULL, 9, 1),
(17, 'Emerging Threat', NULL, 5, 1),
(18, 'RDP Suspicious Logon Attempt', 168, 10, 1),
(19, 'Internal Non-Standard Port Anomaly', NULL, 12, 1),
(20, 'Internal User Login Failure Anomaly', 117, 8, 1),
(21, 'Internal Brute-Forced Successful User Login', 117, 8, 1),
(22, 'Internal Firewall Denial Anomaly', 20, 3, 1),
(23, 'Internal User Application Usage Anomaly', NULL, 3, 1),
(24, 'Internal Account Login Failure Anomaly', 117, 8, 1),
(25, 'External User Login Failure Anomaly', 117, 8, 1),
(26, 'Internal IP / Port Scan Anomaly', 146, 9, 1),
(27, 'Internal User Data Volume Anomaly', 207, 13, 1),
(28, 'External Firewall Policy Anomaly', 87, 7, 1),
(29, 'Internal Credential Stuffing', 117, 8, 1),
(30, 'Internal Firewall Policy Anomaly', 87, 7, 1),
(31, 'WindowsDefenderAntivirus:XDR Miscellaneous Malware', 87, 7, 1),
(32, 'Firewall Policy Anomaly', 88, 7, 1),
(33, 'IP / Port Scan Anomaly', 146, 9, 1),
(34, 'Non-Standard Port Anomaly', NULL, 12, 1),
(35, 'User Data Volume Anomaly', 207, 13, 1),
(36, 'User Login Failure Anomaly', 130, 8, 1),
(262, 'test', 0, 1, 1),
(645, 'PowerShell Remote Access', 27, 4, 4),
(646, 'Encrypted C&C', 194, 12, 4),
(647, 'DHCP Server Anomaly', 21, 3, 4),
(648, 'Malicious Site Access', 16, 2, 4),
(649, 'Mimikatz Credential Dump', 117, 8, 4),
(650, 'Possible Encrypted Phishing Site Visit', 6, 1, 4),
(651, 'Bad Source Reputation Anomaly', 2, 1, 4),
(652, 'DNS Tunneling Anomaly', 200, 12, 4),
(653, 'Outbound Destination Country Anomaly', 18, 1, 4),
(654, 'Bad Destination Reputation Anomaly', 2, 1, 4),
(655, 'Uncommon Application Anomaly', 36, 4, 4),
(656, 'Process Anomaly', 47, 5, 4),
(657, 'Long App Session Anomaly', 166, 10, 4),
(658, 'Impossible Travel Anomaly', 12, 2, 4),
(659, 'Malware in Sharepoint', 165, 10, 4),
(660, 'Short Lived Windows Accounts', 40, 5, 4),
(661, 'Audit Log Cleared', 0, 7, 4),
(662, 'RDP Login Failure', 116, 8, 4),
(663, 'SEPM Infection - Left Alone', 0, 7, 4),
(664, 'User added to security group', 15, 2, 4),
(665, 'Windows System Shutdown or Restart', 0, 14, 4),
(666, 'Software uninstalled on the device', 224, 14, 4),
(667, 'SEPM Services Shutdown', 0, 7, 4),
(668, 'Firewall Shutdown or Restart', 0, 7, 4),
(669, 'Fortigate Firewall Login Failure', 26, 3, 4),
(670, 'Windows Firewall Changes', 0, 7, 4),
(671, 'Fortigate Firewall-Virus Detected', 0, 2, 4),
(672, 'Fortigate Firewall-Medium Severity App-Ctrl Detections ', 189, 12, 4),
(673, 'Fortigate Firewall-High Severity App-Ctrl Detections ', 189, 12, 4),
(674, 'Fortigate Firewall-Low Severity App-Ctrl Detections ', 189, 12, 4),
(675, 'Fortigate Firewall-High Severity IPS detections ', 222, 14, 4),
(676, 'Fortigate Firewall-Medium Severity IPS detections ', 222, 14, 4),
(677, 'Fortigate Firewall-Low Severity IPS Detections ', 222, 14, 4),
(678, 'Fortigate Firewall- Web Filter Detections ', 19, 3, 4),
(679, 'Fortigate Firewall-Low Severity Anomaly Detections ', 189, 12, 4),
(680, 'Fortigate Firewall-High Severity Anomaly Detections ', 189, 12, 4),
(681, 'Fortigate Firewall-Medium Severity Anomaly Detections ', 189, 12, 4),
(682, 'Windows - User Account Change', 40, 5, 4),
(683, 'Windows Local Account Creation', 15, 2, 4),
(684, 'FortiGate Firewall Configuration Change', 0, 7, 4),
(685, 'Office 365 Malware Filter Policy Changed', 0, 7, 4),
(686, 'Emerging Threat', 14, 2, 4),
(687, 'Exploited C&C Connection', 200, 12, 4),
(688, 'Office 365 Sharing Policy Changed', 64, 6, 4),
(689, 'Office 365 Network Security Configuration Changed', 0, 7, 4),
(690, 'Office 365 Multiple Files Restored', 181, 11, 4),
(691, 'RDP Registry Modification', 92, 7, 4),
(692, 'RDP Outbytes Anomaly', 206, 13, 4),
(693, 'Possible Phishing Site Visit from Email', 6, 1, 4),
(694, 'Office 365 Content Filter Policy Changed', 64, 6, 4),
(695, 'Private to Private Exploit Anomaly', 25, 3, 4),
(696, 'Public to Public Exploit Anomaly', 19, 3, 4),
(697, 'Public to Private Exploit Anomaly', 19, 3, 4),
(698, 'Private to Public Exploit Anomaly', 25, 3, 4),
(699, 'Internal Plain Text Passwords Detected', 131, 8, 4),
(700, 'External Plain Text Passwords Detected', 131, 8, 4),
(701, 'Encrypted C& C', 194, 12, 4),
(702, 'Account Login Failure Anomaly', 12, 2, 4),
(703, 'Google Workspace Attack Warning', 20, 3, 4),
(704, 'Google Workspace Suspicious Activities', 26, 3, 4),
(705, 'Google Workspace?User Account Manipulation', 40, 5, 4),
(706, 'Google Workspace?User Suspended', 226, 14, 4),
(707, 'Carbon Black EDR Anomaly', 33, 4, 4),
(708, 'Symantec EP Security Risk Found Alert', 0, 2, 4),
(709, 'AZB - O365 - Operation performed from OWA  login', 0, 3, 4),
(710, 'AZB - O365 - Macos successful User login ', 26, 3, 4),
(711, 'AZB-O365-Multiple Deletion Activity detected from Sent items', 214, 14, 4),
(712, 'AZB  - O365 Deletion Activity from Outside India', 214, 14, 4),
(713, 'Encrypted C& C', 194, 12, 4),
(714, 'Account Login Failure Anomaly', 12, 2, 4),
(715, 'Google Workspace?Attack Warning', 20, 3, 4),
(716, 'Google Workspace Suspicious Activities', 26, 3, 4),
(717, 'Google Workspace?User Account Manipulation', 40, 5, 4),
(718, 'Google Workspace?User Suspended', 226, 14, 4),
(719, 'Carbon Black EDR Anomaly', 33, 4, 4),
(720, 'Handshake Failure', 166, 10, 4),
(721, 'SQL Anomaly', 19, 3, 4),
(722, 'SMB Write Anomaly', 216, 14, 4),
(723, 'SYN Flood Attacker', 222, 14, 4),
(724, 'SYN Flood Victim', 222, 14, 4),
(725, 'Windows - Process Execution', 38, 4, 4),
(726, 'RDP Brute Force Attacks', 116, 8, 4),
(727, 'O365 Multiple user account deleted', 226, 14, 4),
(728, 'WAF Internal Attacker Anomalies', 26, 5, 4),
(729, 'Office 365 Access Governance Alert', 67, 6, 4),
(730, 'Spyware ', 125, 9, 4),
(731, 'Encoded Powershell scripts', 27, 4, 4),
(732, 'Trojan', 193, 12, 4),
(733, 'Ransomware', 215, 14, 4),
(734, 'ransomware_delete_backup_catalogs', 221, 14, 4),
(735, 'Cloud Account Login Failure Anomaly', 116, 8, 4),
(736, 'Credential Stuffing', 116, 8, 4),
(737, 'Exploited Vulnerablity', 30, 4, 4),
(738, 'SQL Dumpfile Execution', 27, 4, 4),
(739, 'URL Reconnaissance Anomaly', 0, 1, 4),
(740, 'Protocol Account Login Failure Anomaly', 116, 8, 4),
(741, 'RDP Suspicious Outbound', 207, 13, 4),
(742, 'RDP BlueKeep', 200, 12, 4),
(743, 'SMB Username Enumerations', 132, 9, 4),
(744, 'Trojan ', 38, 4, 4),
(745, 'pua', 38, 4, 4),
(746, 'Other Malware', 38, 4, 4),
(747, 'SQL Shell Commands', 27, 4, 4),
(748, 'Firewall Denial Anomaly', 19, 3, 4),
(749, 'Firewall Policy Anomaly', 0, 7, 4),
(750, 'G Suite Attack Warning', 20, 3, 4),
(751, 'G Suite Suspicious Activities', 26, 3, 4),
(752, 'G Suite User Suspended', 226, 14, 4),
(753, 'IP / Port Scan Anomaly', 145, 9, 4),
(754, 'Data Ingestion Anomaly', 219, 14, 4),
(755, 'Non-Standard Port Anomaly', 199, 12, 4),
(756, 'Office 365 User Network Admin ', 40, 5, 4),
(757, 'Office 365 Blocked Users', 226, 14, 4),
(758, 'Phishing URL Detections', 6, 1, 4),
(759, 'PII Leaked', 132, 9, 4),
(760, 'RDP Reverse Tunnels', 167, 10, 4),
(761, 'SMB Read Anomaly', 143, 9, 4),
(762, 'Scanner Behaviour anomaly', 1, 1, 4),
(763, 'User Agent Anomaly', 132, 9, 4),
(764, 'User Application Usage Anomaly', 38, 4, 4),
(765, 'User Data Volume Anomaly', 175, 11, 4),
(766, 'User Login Failure Anomaly', 116, 8, 4),
(767, 'Volume Shadow Copy Deletion Via vssadminedit', 221, 14, 4),
(768, 'Volume Shadow Copy Deletion Via wmicredit', 221, 14, 4),
(769, 'WAF Rule Violation Anomalies', 20, 3, 4),
(770, 'File Creation and deletion', 214, 14, 4),
(771, 'PowerShell Remote Access', 27, 4, 3),
(772, 'Recently Registered Domains', 17, 2, 3),
(773, 'Encrypted C&C', 194, 12, 3),
(774, 'DHCP Server Anomaly', 21, 3, 3),
(775, 'AWS S3 Ransomware', 215, 14, 3),
(776, 'Malware on Disk', 14, 2, 3),
(777, 'Malicious Site Access', 16, 2, 3),
(778, 'DGA', 193, 12, 3),
(779, 'Bad Reputation Login', 116, 8, 3),
(780, 'Cryptojacking', 223, 14, 3),
(781, 'Mimikatz Credential Dump', 117, 8, 3),
(782, 'Possible Unencrypted Phishing Site Visit', 6, 1, 3),
(783, 'Possible Encrypted Phishing Site Visit', 6, 1, 3),
(784, 'Bad Source Reputation Anomaly', 1, 1, 3),
(785, 'DNS Tunneling Anomaly', 207, 13, 3),
(786, 'Uncommon Process Anomaly', 36, 4, 3),
(787, 'Outbound Destination Country Anomaly', 2, 1, 3),
(788, 'File Creation Anomaly', 38, 4, 3),
(789, 'Bad Destination Reputation Anomaly', 2, 1, 3),
(790, 'User Process Usage Anomaly', 151, 9, 3),
(791, 'File Action Anomaly', 216, 14, 3),
(792, 'User Asset Access Anomaly', 181, 11, 3),
(793, 'Scanner Reputation Anomaly', 1, 1, 3),
(794, 'Command Anomaly', 27, 4, 3),
(795, 'Application Usage Anomaly', 38, 4, 3),
(796, 'Abnormal Parent / Child Process', 47, 5, 3),
(797, 'Outbytes Anomaly', 206, 13, 3),
(798, 'Uncommon Application Anomaly', 36, 4, 3),
(799, 'Process Anomaly', 47, 5, 3),
(800, 'Long App Session Anomaly', 116, 8, 3),
(801, 'Command and Control Reputation Anomaly', 189, 12, 3),
(802, 'Login Time Anomaly', 116, 8, 3),
(803, 'Impossible Travel Anomaly', 12, 2, 3),
(804, 'RDP Login Failure', 116, 8, 3),
(805, 'User added to security group', 15, 2, 3),
(806, 'Emerging Threat', 14, 2, 3),
(807, 'Office 365 Data Exfiltration Attempt Anomaly', 211, 13, 3),
(808, 'Office 365 Multiple Users Deleted', 226, 14, 3),
(809, 'Exploited C&C Connection', 200, 12, 3),
(810, 'Office 365 Sharing Policy Changed', 64, 6, 3),
(811, 'Office 365 Access Governance Anomaly', 26, 6, 3),
(812, 'Office 365 Multiple Files Restored', 89, 7, 3),
(813, 'Office 365 Content Filter Policy Changed', 64, 6, 3),
(814, 'Public to Public Exploit Anomaly', 0, 3, 3),
(815, 'Public to Private Exploit Anomaly', 0, 3, 3),
(816, 'Private to Public Exploit Anomaly', 25, 3, 3),
(817, 'Internal Non-Standard Port Anomaly', 199, 12, 3),
(818, 'External User Login Failure Anomaly', 116, 8, 3),
(819, 'External Non-Standard Port Anomaly', 199, 12, 3),
(820, 'Internal User Agent Anomaly', 142, 9, 3),
(821, 'Internal IP / Port Scan Anomaly', 1, 1, 3),
(822, 'External Brute-Forced Successful User Login', 116, 8, 3),
(823, 'Internal URL Reconnaissance Anomaly', 4, 1, 3),
(824, 'Internal Plain Text Passwords Detected', 131, 8, 3),
(825, 'Internal User Data Volume Anomaly', 175, 11, 3),
(826, 'External User Agent Anomaly', 142, 9, 3),
(827, 'External Plain Text Passwords Detected', 131, 8, 3),
(828, 'Internal Credential Stuffing', 116, 8, 3),
(829, 'Internal SQL Anomaly', 0, 3, 3),
(830, 'External Account Login Failure Anomaly', 116, 8, 3),
(831, 'External SQL Anomaly', 0, 3, 3),
(832, 'DLPL - Custom - Microsoft Defender AV - Medium Severity - Suspected File level Detection ', 38, 4, 3),
(833, 'DLPL - Custom - Azure WAF Gateway - Critical Signature Observation - Allowed Mode ', 38, 4, 3),
(834, 'DLPL - Custom - Data Lake Key Vault - Access from Public IP - Success Connection Observation', 116, 8, 3),
(835, 'DLPL - Custom - Data Lake Bastion - Suspected RDP Success Failure - Non DLPL Accounts', 116, 8, 3),
(836, 'DLPL - Custom - Data Lake Key Vault - Access from Public IP - Success Connection Observation', 116, 8, 3),
(837, 'DLPL - Custom - Data Lake Bastion - Suspected RDP Success Failure - Non DLPL Accounts', 116, 8, 3),
(838, 'Handshake Failure', 1, 1, 3),
(839, 'SQL Anomaly', 0, 3, 3),
(840, 'SMB Write Anomaly', 216, 14, 3),
(841, 'SYN Flood Attacker', 222, 14, 3),
(842, 'SYN Flood Victim', 222, 14, 3),
(843, 'Windows - Process Execution', 38, 4, 3),
(844, 'RDP Brute Force Attacks', 116, 8, 3),
(845, 'O365 Multiple user account deleted', 226, 14, 3),
(846, 'WAF Internal Attacker Anomalies', 26, 5, 3),
(847, 'Office 365 Access Governance Alert', 40, 5, 3),
(848, 'Spyware ', 38, 4, 3),
(849, 'Encoded Powershell scripts', 27, 4, 3),
(850, 'Trojan', 38, 4, 3),
(851, 'Ransomware', 215, 14, 3),
(852, 'ransomware_delete_backup_catalogs', 214, 14, 3),
(853, 'Cloud Account Login Failure Anomaly', 116, 8, 3),
(854, 'Credential Stuffing', 116, 8, 3),
(855, 'Exploited Vulnerablity', 0, 3, 3),
(856, 'SQL Dumpfile Execution', 27, 4, 3),
(857, 'URL Reconnaissance Anomaly', 1, 1, 3),
(858, 'Protocol Account Login Failure Anomaly', 116, 8, 3),
(859, 'RDP Suspicious Outbound', 167, 10, 3),
(860, 'RDP BlueKeep', 167, 10, 3),
(861, 'SMB Username Enumerations', 167, 10, 3),
(862, 'Trojan ', 38, 4, 3),
(863, 'pua', 38, 4, 3),
(864, 'Other Malware', 38, 4, 3),
(865, 'SQL Shell Commands', 27, 4, 3),
(866, 'Firewall Denial Anomaly', 222, 14, 3),
(867, 'Firewall Policy Anomaly', 64, 6, 3),
(868, 'G Suite Attack Warning', 38, 4, 3),
(869, 'G Suite Suspicious Activities', 38, 4, 3),
(870, 'G Suite User Suspended', 226, 14, 3),
(871, 'IP / Port Scan Anomaly', 1, 1, 3),
(872, 'Data Ingestion Anomaly', 219, 14, 3),
(873, 'Non-Standard Port Anomaly', 199, 12, 3),
(874, 'Office 365 User Network Admin ', 26, 6, 3),
(875, 'Office 365 Blocked Users', 226, 14, 3),
(876, 'Phishing URL Detections', 0, 3, 3),
(877, 'PII Leaked', 205, 13, 3),
(878, 'RDP Reverse Tunnels', 200, 12, 3),
(879, 'SMB Read Anomaly', 0, 3, 3),
(880, 'Scanner Behavior Anomaly', 1, 1, 3),
(881, 'User Agent Anomaly', 132, 9, 3),
(882, 'User Application Usage Anomaly', 30, 4, 3),
(883, 'User Data Volume Anomaly', 175, 11, 3),
(884, 'User Login Failure Anomaly', 116, 8, 3),
(885, 'Volume Shadow Copy Deletion Via vssadminedit', 27, 4, 3),
(886, 'Volume Shadow Copy Deletion Via wmicredit', 27, 4, 3),
(887, 'WAF Rule Violation Anomalies', 86, 7, 3),
(888, 'byeeeee', 116, 8, 5),
(889, 'hiiiiii', 116, 8, 5);

--
-- Indexes for dumped tables
--

--
-- Indexes for table `accounts`
--
ALTER TABLE `accounts`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `admin`
--
ALTER TABLE `admin`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `categories`
--
ALTER TABLE `categories`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `companies`
--
ALTER TABLE `companies`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `subcategories`
--
ALTER TABLE `subcategories`
  ADD PRIMARY KEY (`id`);

--
-- Indexes for table `usecases`
--
ALTER TABLE `usecases`
  ADD PRIMARY KEY (`id`),
  ADD KEY `FK_usecases_categories` (`category_id`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `accounts`
--
ALTER TABLE `accounts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `admin`
--
ALTER TABLE `admin`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- AUTO_INCREMENT for table `categories`
--
ALTER TABLE `categories`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=15;

--
-- AUTO_INCREMENT for table `companies`
--
ALTER TABLE `companies`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- AUTO_INCREMENT for table `subcategories`
--
ALTER TABLE `subcategories`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=227;

--
-- AUTO_INCREMENT for table `usecases`
--
ALTER TABLE `usecases`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=890;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `usecases`
--
ALTER TABLE `usecases`
  ADD CONSTRAINT `FK_usecases_categories` FOREIGN KEY (`category_id`) REFERENCES `categories` (`id`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
