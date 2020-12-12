-- MySQL dump 10.13  Distrib 5.7.24, for Linux (x86_64)
--
-- Host: localhost    Database: playbook
-- ------------------------------------------------------
-- Server version	5.7.24

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Current Database: `playbook`
--

CREATE DATABASE /*!32312 IF NOT EXISTS*/ `playbook` /*!40100 DEFAULT CHARACTER SET latin1 */;

USE `playbook`;

--
-- Table structure for table `ar_internal_metadata`
--

DROP TABLE IF EXISTS `ar_internal_metadata`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ar_internal_metadata` (
  `key` varchar(255) NOT NULL,
  `value` varchar(255) DEFAULT NULL,
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ar_internal_metadata`
--

LOCK TABLES `ar_internal_metadata` WRITE;
/*!40000 ALTER TABLE `ar_internal_metadata` DISABLE KEYS */;
INSERT INTO `ar_internal_metadata` VALUES ('environment','production','2020-04-26 13:08:38','2020-04-26 13:08:38');
/*!40000 ALTER TABLE `ar_internal_metadata` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `attachments`
--

DROP TABLE IF EXISTS `attachments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `attachments` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `container_id` int(11) DEFAULT NULL,
  `container_type` varchar(30) DEFAULT NULL,
  `filename` varchar(255) NOT NULL DEFAULT '',
  `disk_filename` varchar(255) NOT NULL DEFAULT '',
  `filesize` bigint(20) NOT NULL DEFAULT '0',
  `content_type` varchar(255) DEFAULT '',
  `digest` varchar(64) NOT NULL DEFAULT '',
  `downloads` int(11) NOT NULL DEFAULT '0',
  `author_id` int(11) NOT NULL DEFAULT '0',
  `created_on` timestamp NULL DEFAULT NULL,
  `description` varchar(255) DEFAULT NULL,
  `disk_directory` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `index_attachments_on_author_id` (`author_id`),
  KEY `index_attachments_on_created_on` (`created_on`),
  KEY `index_attachments_on_container_id_and_container_type` (`container_id`,`container_type`),
  KEY `index_attachments_on_disk_filename` (`disk_filename`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `attachments`
--

LOCK TABLES `attachments` WRITE;
/*!40000 ALTER TABLE `attachments` DISABLE KEYS */;
/*!40000 ALTER TABLE `attachments` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_sources`
--

DROP TABLE IF EXISTS `auth_sources`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_sources` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(30) NOT NULL DEFAULT '',
  `name` varchar(60) NOT NULL DEFAULT '',
  `host` varchar(60) DEFAULT NULL,
  `port` int(11) DEFAULT NULL,
  `account` varchar(255) DEFAULT NULL,
  `account_password` varchar(255) DEFAULT '',
  `base_dn` varchar(255) DEFAULT NULL,
  `attr_login` varchar(30) DEFAULT NULL,
  `attr_firstname` varchar(30) DEFAULT NULL,
  `attr_lastname` varchar(30) DEFAULT NULL,
  `attr_mail` varchar(30) DEFAULT NULL,
  `onthefly_register` tinyint(1) NOT NULL DEFAULT '0',
  `tls` tinyint(1) NOT NULL DEFAULT '0',
  `filter` text,
  `timeout` int(11) DEFAULT NULL,
  `verify_peer` tinyint(1) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  KEY `index_auth_sources_on_id_and_type` (`id`,`type`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_sources`
--

LOCK TABLES `auth_sources` WRITE;
/*!40000 ALTER TABLE `auth_sources` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_sources` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `boards`
--

DROP TABLE IF EXISTS `boards`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `boards` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `project_id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL DEFAULT '',
  `description` varchar(255) DEFAULT NULL,
  `position` int(11) DEFAULT NULL,
  `topics_count` int(11) NOT NULL DEFAULT '0',
  `messages_count` int(11) NOT NULL DEFAULT '0',
  `last_message_id` int(11) DEFAULT NULL,
  `parent_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `boards_project_id` (`project_id`),
  KEY `index_boards_on_last_message_id` (`last_message_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `boards`
--

LOCK TABLES `boards` WRITE;
/*!40000 ALTER TABLE `boards` DISABLE KEYS */;
/*!40000 ALTER TABLE `boards` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `changes`
--

DROP TABLE IF EXISTS `changes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `changes` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `changeset_id` int(11) NOT NULL,
  `action` varchar(1) NOT NULL DEFAULT '',
  `path` text NOT NULL,
  `from_path` text,
  `from_revision` varchar(255) DEFAULT NULL,
  `revision` varchar(255) DEFAULT NULL,
  `branch` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `changesets_changeset_id` (`changeset_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `changes`
--

LOCK TABLES `changes` WRITE;
/*!40000 ALTER TABLE `changes` DISABLE KEYS */;
/*!40000 ALTER TABLE `changes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `changeset_parents`
--

DROP TABLE IF EXISTS `changeset_parents`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `changeset_parents` (
  `changeset_id` int(11) NOT NULL,
  `parent_id` int(11) NOT NULL,
  KEY `changeset_parents_changeset_ids` (`changeset_id`),
  KEY `changeset_parents_parent_ids` (`parent_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `changeset_parents`
--

LOCK TABLES `changeset_parents` WRITE;
/*!40000 ALTER TABLE `changeset_parents` DISABLE KEYS */;
/*!40000 ALTER TABLE `changeset_parents` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `changesets`
--

DROP TABLE IF EXISTS `changesets`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `changesets` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `repository_id` int(11) NOT NULL,
  `revision` varchar(255) NOT NULL,
  `committer` varchar(255) DEFAULT NULL,
  `committed_on` datetime NOT NULL,
  `comments` longtext,
  `commit_date` date DEFAULT NULL,
  `scmid` varchar(255) DEFAULT NULL,
  `user_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `changesets_repos_rev` (`repository_id`,`revision`),
  KEY `index_changesets_on_user_id` (`user_id`),
  KEY `index_changesets_on_repository_id` (`repository_id`),
  KEY `index_changesets_on_committed_on` (`committed_on`),
  KEY `changesets_repos_scmid` (`repository_id`,`scmid`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `changesets`
--

LOCK TABLES `changesets` WRITE;
/*!40000 ALTER TABLE `changesets` DISABLE KEYS */;
/*!40000 ALTER TABLE `changesets` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `changesets_issues`
--

DROP TABLE IF EXISTS `changesets_issues`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `changesets_issues` (
  `changeset_id` int(11) NOT NULL,
  `issue_id` int(11) NOT NULL,
  UNIQUE KEY `changesets_issues_ids` (`changeset_id`,`issue_id`),
  KEY `index_changesets_issues_on_issue_id` (`issue_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `changesets_issues`
--

LOCK TABLES `changesets_issues` WRITE;
/*!40000 ALTER TABLE `changesets_issues` DISABLE KEYS */;
/*!40000 ALTER TABLE `changesets_issues` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `comments`
--

DROP TABLE IF EXISTS `comments`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `comments` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `commented_type` varchar(30) NOT NULL DEFAULT '',
  `commented_id` int(11) NOT NULL DEFAULT '0',
  `author_id` int(11) NOT NULL DEFAULT '0',
  `content` text,
  `created_on` datetime NOT NULL,
  `updated_on` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index_comments_on_commented_id_and_commented_type` (`commented_id`,`commented_type`),
  KEY `index_comments_on_author_id` (`author_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `comments`
--

LOCK TABLES `comments` WRITE;
/*!40000 ALTER TABLE `comments` DISABLE KEYS */;
/*!40000 ALTER TABLE `comments` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `custom_field_enumerations`
--

DROP TABLE IF EXISTS `custom_field_enumerations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `custom_field_enumerations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `custom_field_id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `active` tinyint(1) NOT NULL DEFAULT '1',
  `position` int(11) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `custom_field_enumerations`
--

LOCK TABLES `custom_field_enumerations` WRITE;
/*!40000 ALTER TABLE `custom_field_enumerations` DISABLE KEYS */;
/*!40000 ALTER TABLE `custom_field_enumerations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `custom_fields`
--

DROP TABLE IF EXISTS `custom_fields`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `custom_fields` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(30) NOT NULL DEFAULT '',
  `name` varchar(30) NOT NULL DEFAULT '',
  `field_format` varchar(30) NOT NULL DEFAULT '',
  `possible_values` text,
  `regexp` varchar(255) DEFAULT '',
  `min_length` int(11) DEFAULT NULL,
  `max_length` int(11) DEFAULT NULL,
  `is_required` tinyint(1) NOT NULL DEFAULT '0',
  `is_for_all` tinyint(1) NOT NULL DEFAULT '0',
  `is_filter` tinyint(1) NOT NULL DEFAULT '0',
  `position` int(11) DEFAULT NULL,
  `searchable` tinyint(1) DEFAULT '0',
  `default_value` text,
  `editable` tinyint(1) DEFAULT '1',
  `visible` tinyint(1) NOT NULL DEFAULT '1',
  `multiple` tinyint(1) DEFAULT '0',
  `format_store` text,
  `description` text,
  PRIMARY KEY (`id`),
  KEY `index_custom_fields_on_id_and_type` (`id`,`type`)
) ENGINE=InnoDB AUTO_INCREMENT=41 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `custom_fields`
--

LOCK TABLES `custom_fields` WRITE;
/*!40000 ALTER TABLE `custom_fields` DISABLE KEYS */;
INSERT INTO `custom_fields` VALUES (1,'IssueCustomField','Title','string',NULL,'',NULL,NULL,0,1,1,1,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: \'\'\nurl_pattern: \'\'\n',''),(2,'IssueCustomField','Author','string',NULL,'',NULL,NULL,0,1,1,2,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: \'\'\nurl_pattern: \'\'\n',''),(3,'IssueCustomField','Objective','text',NULL,'',NULL,NULL,0,1,1,16,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: \'\'\nfull_width_layout: \'1\'\n',''),(4,'IssueCustomField','Operational Notes','text',NULL,'',NULL,NULL,0,1,0,17,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: full\nfull_width_layout: \'1\'\n',''),(5,'IssueCustomField','Result Analysis','text',NULL,'',NULL,NULL,0,1,0,18,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: full\nfull_width_layout: \'1\'\n',''),(6,'IssueCustomField','ElastAlert Config','text',NULL,'',NULL,NULL,0,1,0,19,0,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: full\nfull_width_layout: \'1\'\n',''),(7,'IssueCustomField','HiveID','string',NULL,'',NULL,NULL,0,1,1,15,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: \'\'\nurl_pattern: \'\'\n',''),(8,'IssueCustomField','References','text',NULL,'',NULL,NULL,0,1,0,6,0,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: full\nfull_width_layout: \'0\'\n',''),(9,'IssueCustomField','Sigma','text',NULL,'',NULL,NULL,0,1,0,20,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: full\nfull_width_layout: \'1\'\n',''),(10,'IssueCustomField','Level','list','---\n- low\n- medium\n- high\n- critical\n','',NULL,NULL,0,1,1,3,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: \'\'\nedit_tag_style: \'\'\n',''),(11,'IssueCustomField','PlayID','string',NULL,'',NULL,NULL,0,1,1,8,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: \'\'\nurl_pattern: \'\'\n',''),(12,'IssueCustomField','Rule ID','string',NULL,'',NULL,NULL,0,1,1,9,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: \'\'\nurl_pattern: \'\'\n',''),(13,'IssueCustomField','Playbook','list','---\n- Internal\n- imported\n- community\n','',NULL,NULL,0,1,1,4,0,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: \'\'\nedit_tag_style: \'\'\n',''),(15,'IssueCustomField','ATT&CK Technique','list','---\n- T1001\n- T1002\n- T1003\n- T1004\n- T1005\n- T1006\n- T1007\n- T1008\n- T1009\n- T1010\n- T1011\n- T1012\n- T1013\n- T1014\n- T1015\n- T1016\n- T1017\n- T1018\n- T1019\n- T1020\n- T1021\n- T1022\n- T1023\n- T1024\n- T1025\n- T1026\n- T1027\n- T1028\n- T1029\n- T1030\n- T1031\n- T1032\n- T1033\n- T1034\n- T1035\n- T1036\n- T1037\n- T1038\n- T1039\n- T1040\n- T1041\n- T1042\n- T1043\n- T1044\n- T1045\n- T1046\n- T1047\n- T1048\n- T1049\n- T1050\n- T1051\n- T1052\n- T1053\n- T1054\n- T1055\n- T1056\n- T1057\n- T1058\n- T1059\n- T1060\n- T1061\n- T1062\n- T1063\n- T1064\n- T1065\n- T1066\n- T1067\n- T1068\n- T1069\n- T1070\n- T1071\n- T1072\n- T1073\n- T1074\n- T1075\n- T1076\n- T1077\n- T1078\n- T1079\n- T1080\n- T1081\n- T1082\n- T1083\n- T1084\n- T1085\n- T1086\n- T1087\n- T1088\n- T1089\n- T1090\n- T1091\n- T1092\n- T1093\n- T1094\n- T1095\n- T1096\n- T1097\n- T1098\n- T1099\n- T1100\n- T1101\n- T1102\n- T1103\n- T1104\n- T1105\n- T1106\n- T1107\n- T1108\n- T1109\n- T1110\n- T1111\n- T1112\n- T1113\n- T1114\n- T1115\n- T1116\n- T1117\n- T1118\n- T1119\n- T1120\n- T1121\n- T1122\n- T1123\n- T1124\n- T1125\n- T1126\n- T1127\n- T1128\n- T1129\n- T1130\n- T1131\n- T1132\n- T1133\n- T1134\n- T1135\n- T1136\n- T1137\n- T1138\n- T1139\n- T1140\n- T1141\n- T1142\n- T1143\n- T1144\n- T1145\n- T1146\n- T1147\n- T1148\n- T1149\n- T1150\n- T1151\n- T1152\n- T1153\n- T1154\n- T1155\n- T1156\n- T1157\n- T1158\n- T1159\n- T1160\n- T1161\n- T1162\n- T1163\n- T1164\n- T1165\n- T1166\n- T1167\n- T1168\n- T1169\n- T1170\n- T1171\n- T1172\n- T1173\n- T1174\n- T1175\n- T1176\n- T1177\n- T1178\n- T1179\n- T1180\n- T1181\n- T1182\n- T1183\n- T1184\n- T1185\n- T1186\n- T1187\n- T1188\n- T1189\n- T1190\n- T1191\n- T1192\n- T1193\n- T1194\n- T1195\n- T1196\n- T1197\n- T1198\n- T1199\n- T1200\n- T1201\n- T1202\n- T1203\n- T1204\n- T1205\n- T1206\n- T1207\n- T1208\n- T1209\n- T1210\n- T1211\n- T1212\n- T1213\n- T1214\n- T1215\n- T1216\n- T1217\n- T1218\n- T1219\n- T1220\n- T1221\n- T1222\n- T1223\n- T1480\n- T1482\n- T1483\n- T1484\n- T1485\n- T1486\n- T1487\n- T1488\n- T1489\n- T1490\n- T1491\n- T1492\n- T1493\n- T1494\n- T1495\n- T1496\n- T1497\n- T1498\n- T1499\n- T1500\n- T1501\n- T1502\n- T1503\n- T1504\n- T1505\n- T1506\n- T1514\n- T1518\n- T1519\n- T1522\n- T1525\n- T1526\n- T1527\n- T1528\n- T1529\n- T1530\n- T1531\n- T1534\n- T1535\n- T1536\n- T1537\n- T1538\n- T1539\n- T1540\n- T1541\n- T1542\n- T1543\n- T1544\n- T1545\n- T1546\n- T1547\n- T1548\n- T1549\n- T1550\n- T1551\n- T1552\n- T1553\n- T1554\n- T1555\n- T1556\n- T1557\n- T1558\n- T1559\n- T1560\n- T1561\n- T1562\n- T1563\n- T1564\n- T1565\n- T1566\n- T1567\n- T1568\n- T1569\n- T1570\n- T1571\n- T1572\n- T1573\n- T1574\n- T1575\n- T1576\n- T1577\n- T1578\n- T1579\n- T1580\n- T1581\n- T1582\n- T1583\n- T1584\n- T1585\n- T1586\n- T1587\n- T1588\n- T1589\n- T1590\n- T1591\n- T1592\n- T1593\n- T1594\n- T1595\n- T1596\n- T1597\n- T1598\n- T1599\n- T1600\n- T1601\n- T1602\n- T1603\n- T1604\n- T1605\n- T1606\n- T1607\n- T1608\n- T1609\n- T1610\n- T1611\n- T1612\n- T1613\n- T1614\n- T1615\n- T1616\n- T1617\n- T1618\n- T1619\n- T1620\n- T1621\n- T1622\n- T1623\n- T1624\n- T1625\n- T1626\n- T1627\n- T1628\n- T1629\n- T1630\n- T1631\n- T1632\n- T1633\n- T1634\n- T1635\n- T1636\n- T1637\n- T1638\n- T1639\n- T1640\n- T1641\n- T1642\n- T1643\n- T1644\n- T1645\n- T1646\n- T1647\n- T1648\n- T1649\n- T1650\n- T1651\n- T1652\n- T1653\n- T1654\n- T1655\n- T1656\n- T1657\n- T1658\n- T1659\n- T1660\n- T1661\n- T1662\n- T1663\n- T1664\n- T1665\n- T1666\n- T1667\n- T1668\n- T1669\n- T1670\n- T1671\n- T1672\n- T1673\n- T1674\n- T1675\n- T1676\n- T1677\n- T1678\n- T1679\n- T1680\n- T1681\n- T1682\n- T1683\n- T1684\n- T1685\n- T1686\n- T1687\n- T1688\n- T1689\n- T1690\n- T1691\n- T1692\n- T1693\n- T1694\n- T1695\n- T1696\n- T1697\n- T1698\n- T1699\n- T1700\n- T1701\n- T1702\n- T1703\n- T1704\n- T1705\n- T1706\n- T1707\n- T1708\n- T1709\n- T1710\n- T1711\n- T1712\n- T1713\n- T1714\n- T1715\n- T1716\n- T1717\n- T1718\n- T1719\n- T1720\n- T1721\n- T1722\n- T1723\n- T1724\n- T1725\n- T1726\n- T1727\n- T1728\n- T1729\n- T1730\n- T1731\n- T1732\n- T1733\n- T1734\n- T1735\n- T1736\n- T1737\n- T1738\n- T1739\n- T1740\n- T1741\n- T1742\n- T1743\n- T1744\n- T1745\n- T1746\n- T1747\n- T1748\n- T1749\n- T1750\n- T1751\n- T1752\n','',NULL,NULL,0,1,1,7,0,'',1,1,1,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: https://attack.mitre.org/techniques/%value%\nedit_tag_style: \'\'\n',''),(17,'IssueCustomField','Case Analyzers','list','---\n- Urlscan_io_Search - ip,domain,hash,url\n- CERTatPassiveDNS - domain,fqdn,ip\n','',NULL,NULL,0,1,1,14,1,'',1,1,1,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: \'\'\nedit_tag_style: \'\'\n',''),(18,'IssueCustomField','Ruleset','string',NULL,'',NULL,NULL,0,1,1,12,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: \'\'\nurl_pattern: \'\'\n',''),(19,'IssueCustomField','Group','string',NULL,'',NULL,NULL,0,1,1,13,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: \'\'\nurl_pattern: \'\'\n',''),(20,'IssueCustomField','Product','string',NULL,'',NULL,NULL,0,1,1,5,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: \'\'\nurl_pattern: \'\'\n',''),(21,'IssueCustomField','Target Log','text',NULL,'',NULL,NULL,0,1,0,21,0,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: full\nfull_width_layout: \'1\'\n',''),(22,'IssueCustomField','Unit Test','list','---\n- Passed\n- Failed\n','',NULL,NULL,0,1,1,22,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: \'\'\nedit_tag_style: \'\'\n',''),(26,'IssueCustomField','License','list','---\n- Apache-2.0\n- BSD-2-Clause\n- BSD-3-Clause\n- CC0-1.0\n- CC-PDDC\n- DRL-1.0\n- LGPL-3.0-only\n- MIT License\n- GPL-2.0-only\n- GPL-3.0-only\n','',NULL,NULL,0,1,0,23,0,'',1,1,1,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: https://spdx.org/licenses/%value%.html\nedit_tag_style: \'\'\n',''),(27,'IssueCustomField','Sigma File','string',NULL,'',NULL,NULL,0,0,0,10,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: \'\'\nurl_pattern: \'\'\n','Location of Sigma file in /SOCtopus'),(28,'IssueCustomField','Sigma URL','string',NULL,'',NULL,NULL,0,0,0,11,1,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: full\n','Location of Sigma file in Security Onion repository'),(29,'IssueCustomField','Email Notifications','bool',NULL,'',NULL,NULL,1,0,1,25,0,'0',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: \'\'\nedit_tag_style: check_box\n','When enabled, all alerts will be logged in SOC Alerts and also emailed to the target email address. To configure email options, go to \"jump to a project\" in the top right and type Options. Configure SMTP Settings.'),(30,'IssueCustomField','Auto Update Sigma','bool',NULL,'',NULL,NULL,1,0,1,26,0,'1',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: \'\'\nedit_tag_style: check_box\n','Automatically updating a sigma will be a scheduled task that removes any custom configuration done to the sigma. If you want to customize (ie. add exclusions), automatic updating must be disabled. '),(31,'IssueCustomField','Update Available','bool',NULL,'',NULL,NULL,1,0,1,27,0,'0',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: \'\'\nedit_tag_style: \'\'\n','The update available field notifies you that a sigma has been updated in the public repo. If a rule doesn\'t automatically update, this field will let you know to either enable automatic updates or manually review the rule changes in the repo. Set this value back to No to ignore the rule notification.'),(32,'IssueCustomField','Alert Email Address','string',NULL,'',NULL,NULL,0,0,0,28,0,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: \'\'\nurl_pattern: \'\'\n','Destination address for email alerts'),(33,'IssueCustomField','Alert From Email Address','string',NULL,'',NULL,NULL,0,0,0,29,0,'alerts@localhost.local',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: \'\'\nurl_pattern: \'\'\n','Source address for email alerts'),(34,'IssueCustomField','SMTP Server','string',NULL,'',NULL,NULL,0,0,0,30,0,'',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\ntext_formatting: \'\'\nurl_pattern: \'\'\n','IP Address/Name of destination SMTP Server'),(35,'IssueCustomField','SMTP Port','int',NULL,'',NULL,NULL,0,0,0,31,0,'25',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: \'\'\n','Destination port of SMTP Server'),(36,'IssueCustomField','SMTP TLS Enabled','bool',NULL,'',NULL,NULL,1,0,0,32,0,'0',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: \'\'\nedit_tag_style: \'\'\n','Enable if SMTP server is requires TLS'),(37,'IssueCustomField','Backup Custom Sigmas','bool',NULL,'',NULL,NULL,1,0,0,33,0,'0',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: \'\'\nedit_tag_style: \'\'\n','Backup custom community sigmas and internal sigmas to /SOCtopus/custom/backup'),(38,'IssueCustomField','Import Custom Sigmas','bool',NULL,'',NULL,NULL,1,0,0,34,0,'0',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: \'\'\nedit_tag_style: \'\'\n','Import custom rules from /SOCtopus/custom/import'),(39,'IssueCustomField','Clear Update Status (all)','bool',NULL,'',NULL,NULL,1,0,0,35,0,'0',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: \'\'\nedit_tag_style: \'\'\n','Reset \"Update Available\" status on all rules'),(40,'IssueCustomField','Disable Playbook Alerts','bool',NULL,'',NULL,NULL,1,0,1,24,0,'0',1,1,0,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nurl_pattern: \'\'\nedit_tag_style: check_box\n','Playbook will not generate any alerts for this Play');
/*!40000 ALTER TABLE `custom_fields` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `custom_fields_projects`
--

DROP TABLE IF EXISTS `custom_fields_projects`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `custom_fields_projects` (
  `custom_field_id` int(11) NOT NULL DEFAULT '0',
  `project_id` int(11) NOT NULL DEFAULT '0',
  UNIQUE KEY `index_custom_fields_projects_on_custom_field_id_and_project_id` (`custom_field_id`,`project_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `custom_fields_projects`
--

LOCK TABLES `custom_fields_projects` WRITE;
/*!40000 ALTER TABLE `custom_fields_projects` DISABLE KEYS */;
INSERT INTO `custom_fields_projects` VALUES (27,1),(28,1),(29,1),(30,1),(31,1),(32,2),(33,2),(34,2),(35,2),(36,2),(37,2),(38,2),(39,2),(40,1);
/*!40000 ALTER TABLE `custom_fields_projects` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `custom_fields_roles`
--

DROP TABLE IF EXISTS `custom_fields_roles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `custom_fields_roles` (
  `custom_field_id` int(11) NOT NULL,
  `role_id` int(11) NOT NULL,
  UNIQUE KEY `custom_fields_roles_ids` (`custom_field_id`,`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `custom_fields_roles`
--

LOCK TABLES `custom_fields_roles` WRITE;
/*!40000 ALTER TABLE `custom_fields_roles` DISABLE KEYS */;
/*!40000 ALTER TABLE `custom_fields_roles` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `custom_fields_trackers`
--

DROP TABLE IF EXISTS `custom_fields_trackers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `custom_fields_trackers` (
  `custom_field_id` int(11) NOT NULL DEFAULT '0',
  `tracker_id` int(11) NOT NULL DEFAULT '0',
  UNIQUE KEY `index_custom_fields_trackers_on_custom_field_id_and_tracker_id` (`custom_field_id`,`tracker_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `custom_fields_trackers`
--

LOCK TABLES `custom_fields_trackers` WRITE;
/*!40000 ALTER TABLE `custom_fields_trackers` DISABLE KEYS */;
INSERT INTO `custom_fields_trackers` VALUES (1,1),(1,2),(1,3),(2,1),(3,1),(4,1),(5,1),(6,1),(7,1),(8,1),(9,1),(10,1),(11,1),(12,1),(13,1),(15,1),(17,1),(18,1),(19,1),(20,1),(21,1),(22,1),(26,1),(27,1),(28,1),(29,1),(30,1),(31,1),(32,2),(33,2),(34,2),(35,2),(36,2),(37,3),(38,3),(39,3),(40,1);
/*!40000 ALTER TABLE `custom_fields_trackers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `custom_values`
--

DROP TABLE IF EXISTS `custom_values`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `custom_values` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `customized_type` varchar(30) NOT NULL DEFAULT '',
  `customized_id` int(11) NOT NULL DEFAULT '0',
  `custom_field_id` int(11) NOT NULL DEFAULT '0',
  `value` longtext,
  PRIMARY KEY (`id`),
  KEY `custom_values_customized` (`customized_type`,`customized_id`),
  KEY `index_custom_values_on_custom_field_id` (`custom_field_id`)
) ENGINE=InnoDB AUTO_INCREMENT=186336 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `custom_values`
--

LOCK TABLES `custom_values` WRITE;
/*!40000 ALTER TABLE `custom_values` DISABLE KEYS */;
INSERT INTO `custom_values` VALUES (170104,'Issue',995,1,'Sigma Options'),(170105,'Issue',995,37,'1'),(170106,'Issue',995,38,'0'),(170107,'Issue',995,39,'0');
/*!40000 ALTER TABLE `custom_values` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `documents`
--

DROP TABLE IF EXISTS `documents`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `documents` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `project_id` int(11) NOT NULL DEFAULT '0',
  `category_id` int(11) NOT NULL DEFAULT '0',
  `title` varchar(255) NOT NULL DEFAULT '',
  `description` text,
  `created_on` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `documents_project_id` (`project_id`),
  KEY `index_documents_on_category_id` (`category_id`),
  KEY `index_documents_on_created_on` (`created_on`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `documents`
--

LOCK TABLES `documents` WRITE;
/*!40000 ALTER TABLE `documents` DISABLE KEYS */;
/*!40000 ALTER TABLE `documents` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `email_addresses`
--

DROP TABLE IF EXISTS `email_addresses`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `email_addresses` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `address` varchar(255) NOT NULL,
  `is_default` tinyint(1) NOT NULL DEFAULT '0',
  `notify` tinyint(1) NOT NULL DEFAULT '1',
  `created_on` datetime NOT NULL,
  `updated_on` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `index_email_addresses_on_user_id` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `email_addresses`
--

LOCK TABLES `email_addresses` WRITE;
/*!40000 ALTER TABLE `email_addresses` DISABLE KEYS */;
INSERT INTO `email_addresses` VALUES (1,1,'admin@example.net',1,1,'2020-04-26 13:08:38','2020-04-26 13:08:38'),(3,9,'automation@localhost.local',1,1,'2020-04-26 18:47:46','2020-04-26 18:47:46'),(4,10,'automation2@localhost.local',1,1,'2020-11-21 22:14:13','2020-11-21 22:14:13');
/*!40000 ALTER TABLE `email_addresses` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `enabled_modules`
--

DROP TABLE IF EXISTS `enabled_modules`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `enabled_modules` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `project_id` int(11) DEFAULT NULL,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `enabled_modules_project_id` (`project_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `enabled_modules`
--

LOCK TABLES `enabled_modules` WRITE;
/*!40000 ALTER TABLE `enabled_modules` DISABLE KEYS */;
INSERT INTO `enabled_modules` VALUES (1,1,'sigma_editor'),(2,1,'issue_tracking'),(3,2,'sigma_editor'),(4,2,'issue_tracking');
/*!40000 ALTER TABLE `enabled_modules` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `enumerations`
--

DROP TABLE IF EXISTS `enumerations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `enumerations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(30) NOT NULL DEFAULT '',
  `position` int(11) DEFAULT NULL,
  `is_default` tinyint(1) NOT NULL DEFAULT '0',
  `type` varchar(255) DEFAULT NULL,
  `active` tinyint(1) NOT NULL DEFAULT '1',
  `project_id` int(11) DEFAULT NULL,
  `parent_id` int(11) DEFAULT NULL,
  `position_name` varchar(30) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `index_enumerations_on_project_id` (`project_id`),
  KEY `index_enumerations_on_id_and_type` (`id`,`type`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `enumerations`
--

LOCK TABLES `enumerations` WRITE;
/*!40000 ALTER TABLE `enumerations` DISABLE KEYS */;
INSERT INTO `enumerations` VALUES (1,'Normal',1,1,'IssuePriority',1,NULL,NULL,'default');
/*!40000 ALTER TABLE `enumerations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `groups_users`
--

DROP TABLE IF EXISTS `groups_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `groups_users` (
  `group_id` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  UNIQUE KEY `groups_users_ids` (`group_id`,`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `groups_users`
--

LOCK TABLES `groups_users` WRITE;
/*!40000 ALTER TABLE `groups_users` DISABLE KEYS */;
INSERT INTO `groups_users` VALUES (6,10),(7,1);
/*!40000 ALTER TABLE `groups_users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `import_items`
--

DROP TABLE IF EXISTS `import_items`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `import_items` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `import_id` int(11) NOT NULL,
  `position` int(11) NOT NULL,
  `obj_id` int(11) DEFAULT NULL,
  `message` text,
  `unique_id` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `index_import_items_on_import_id_and_unique_id` (`import_id`,`unique_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `import_items`
--

LOCK TABLES `import_items` WRITE;
/*!40000 ALTER TABLE `import_items` DISABLE KEYS */;
/*!40000 ALTER TABLE `import_items` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `imports`
--

DROP TABLE IF EXISTS `imports`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `imports` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(255) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  `filename` varchar(255) DEFAULT NULL,
  `settings` text,
  `total_items` int(11) DEFAULT NULL,
  `finished` tinyint(1) NOT NULL DEFAULT '0',
  `created_at` datetime NOT NULL,
  `updated_at` datetime NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `imports`
--

LOCK TABLES `imports` WRITE;
/*!40000 ALTER TABLE `imports` DISABLE KEYS */;
/*!40000 ALTER TABLE `imports` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `issue_categories`
--

DROP TABLE IF EXISTS `issue_categories`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `issue_categories` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `project_id` int(11) NOT NULL DEFAULT '0',
  `name` varchar(60) NOT NULL DEFAULT '',
  `assigned_to_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `issue_categories_project_id` (`project_id`),
  KEY `index_issue_categories_on_assigned_to_id` (`assigned_to_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `issue_categories`
--

LOCK TABLES `issue_categories` WRITE;
/*!40000 ALTER TABLE `issue_categories` DISABLE KEYS */;
/*!40000 ALTER TABLE `issue_categories` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `issue_relations`
--

DROP TABLE IF EXISTS `issue_relations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `issue_relations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `issue_from_id` int(11) NOT NULL,
  `issue_to_id` int(11) NOT NULL,
  `relation_type` varchar(255) NOT NULL DEFAULT '',
  `delay` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `index_issue_relations_on_issue_from_id_and_issue_to_id` (`issue_from_id`,`issue_to_id`),
  KEY `index_issue_relations_on_issue_from_id` (`issue_from_id`),
  KEY `index_issue_relations_on_issue_to_id` (`issue_to_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `issue_relations`
--

LOCK TABLES `issue_relations` WRITE;
/*!40000 ALTER TABLE `issue_relations` DISABLE KEYS */;
/*!40000 ALTER TABLE `issue_relations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `issue_statuses`
--

DROP TABLE IF EXISTS `issue_statuses`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `issue_statuses` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(30) NOT NULL DEFAULT '',
  `is_closed` tinyint(1) NOT NULL DEFAULT '0',
  `position` int(11) DEFAULT NULL,
  `default_done_ratio` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `index_issue_statuses_on_position` (`position`),
  KEY `index_issue_statuses_on_is_closed` (`is_closed`)
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `issue_statuses`
--

LOCK TABLES `issue_statuses` WRITE;
/*!40000 ALTER TABLE `issue_statuses` DISABLE KEYS */;
INSERT INTO `issue_statuses` VALUES (2,'Draft',0,1,NULL),(3,'Active',0,2,NULL),(4,'Inactive',0,3,NULL),(5,'Archived',0,4,NULL),(6,'Disabled',0,5,NULL);
/*!40000 ALTER TABLE `issue_statuses` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `issues`
--

DROP TABLE IF EXISTS `issues`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `issues` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tracker_id` int(11) NOT NULL,
  `project_id` int(11) NOT NULL,
  `subject` varchar(255) NOT NULL DEFAULT '',
  `description` longtext,
  `due_date` date DEFAULT NULL,
  `category_id` int(11) DEFAULT NULL,
  `status_id` int(11) NOT NULL,
  `assigned_to_id` int(11) DEFAULT NULL,
  `priority_id` int(11) NOT NULL,
  `fixed_version_id` int(11) DEFAULT NULL,
  `author_id` int(11) NOT NULL,
  `lock_version` int(11) NOT NULL DEFAULT '0',
  `created_on` timestamp NULL DEFAULT NULL,
  `updated_on` timestamp NULL DEFAULT NULL,
  `start_date` date DEFAULT NULL,
  `done_ratio` int(11) NOT NULL DEFAULT '0',
  `estimated_hours` float DEFAULT NULL,
  `parent_id` int(11) DEFAULT NULL,
  `root_id` int(11) DEFAULT NULL,
  `lft` int(11) DEFAULT NULL,
  `rgt` int(11) DEFAULT NULL,
  `is_private` tinyint(1) NOT NULL DEFAULT '0',
  `closed_on` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `issues_project_id` (`project_id`),
  KEY `index_issues_on_status_id` (`status_id`),
  KEY `index_issues_on_category_id` (`category_id`),
  KEY `index_issues_on_assigned_to_id` (`assigned_to_id`),
  KEY `index_issues_on_fixed_version_id` (`fixed_version_id`),
  KEY `index_issues_on_tracker_id` (`tracker_id`),
  KEY `index_issues_on_priority_id` (`priority_id`),
  KEY `index_issues_on_author_id` (`author_id`),
  KEY `index_issues_on_created_on` (`created_on`),
  KEY `index_issues_on_root_id_and_lft_and_rgt` (`root_id`,`lft`,`rgt`),
  KEY `index_issues_on_parent_id` (`parent_id`)
) ENGINE=InnoDB AUTO_INCREMENT=996 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `issues`
--

LOCK TABLES `issues` WRITE;
/*!40000 ALTER TABLE `issues` DISABLE KEYS */;
INSERT INTO `issues` VALUES (995,3,2,'Sigma Options',NULL,NULL,NULL,2,NULL,1,NULL,1,0,'2020-11-23 15:17:38','2020-11-23 15:17:38',NULL,0,NULL,NULL,995,1,2,0,NULL);
/*!40000 ALTER TABLE `issues` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `journal_details`
--

DROP TABLE IF EXISTS `journal_details`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `journal_details` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `journal_id` int(11) NOT NULL DEFAULT '0',
  `property` varchar(30) NOT NULL DEFAULT '',
  `prop_key` varchar(30) NOT NULL DEFAULT '',
  `old_value` longtext,
  `value` longtext,
  PRIMARY KEY (`id`),
  KEY `journal_details_journal_id` (`journal_id`)
) ENGINE=InnoDB AUTO_INCREMENT=456 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `journal_details`
--

LOCK TABLES `journal_details` WRITE;
/*!40000 ALTER TABLE `journal_details` DISABLE KEYS */;
/*!40000 ALTER TABLE `journal_details` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `journals`
--

DROP TABLE IF EXISTS `journals`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `journals` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `journalized_id` int(11) NOT NULL DEFAULT '0',
  `journalized_type` varchar(30) NOT NULL DEFAULT '',
  `user_id` int(11) NOT NULL DEFAULT '0',
  `notes` longtext,
  `created_on` datetime NOT NULL,
  `private_notes` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `journals_journalized_id` (`journalized_id`,`journalized_type`),
  KEY `index_journals_on_user_id` (`user_id`),
  KEY `index_journals_on_journalized_id` (`journalized_id`),
  KEY `index_journals_on_created_on` (`created_on`)
) ENGINE=InnoDB AUTO_INCREMENT=11351 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `journals`
--

LOCK TABLES `journals` WRITE;
/*!40000 ALTER TABLE `journals` DISABLE KEYS */;
/*!40000 ALTER TABLE `journals` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `member_roles`
--

DROP TABLE IF EXISTS `member_roles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `member_roles` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `member_id` int(11) NOT NULL,
  `role_id` int(11) NOT NULL,
  `inherited_from` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `index_member_roles_on_member_id` (`member_id`),
  KEY `index_member_roles_on_role_id` (`role_id`),
  KEY `index_member_roles_on_inherited_from` (`inherited_from`)
) ENGINE=InnoDB AUTO_INCREMENT=21 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `member_roles`
--

LOCK TABLES `member_roles` WRITE;
/*!40000 ALTER TABLE `member_roles` DISABLE KEYS */;
INSERT INTO `member_roles` VALUES (1,1,5,NULL),(2,2,3,NULL),(3,3,4,NULL),(4,4,5,1),(7,7,4,3),(8,8,5,1),(9,9,3,NULL),(10,9,4,NULL),(11,9,5,NULL),(12,10,3,NULL),(13,10,4,NULL),(14,10,5,NULL),(15,11,3,NULL),(16,10,3,15),(17,11,4,NULL),(18,10,4,17),(19,11,5,NULL),(20,10,5,19);
/*!40000 ALTER TABLE `member_roles` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `members`
--

DROP TABLE IF EXISTS `members`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `members` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL DEFAULT '0',
  `project_id` int(11) NOT NULL DEFAULT '0',
  `created_on` timestamp NULL DEFAULT NULL,
  `mail_notification` tinyint(1) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  UNIQUE KEY `index_members_on_user_id_and_project_id` (`user_id`,`project_id`),
  KEY `index_members_on_user_id` (`user_id`),
  KEY `index_members_on_project_id` (`project_id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `members`
--

LOCK TABLES `members` WRITE;
/*!40000 ALTER TABLE `members` DISABLE KEYS */;
INSERT INTO `members` VALUES (1,6,1,'2020-04-26 18:44:14',0),(2,5,1,'2020-04-26 18:44:23',0),(3,7,1,'2020-04-26 18:45:27',0),(4,9,1,'2020-04-26 18:47:51',0),(7,1,1,'2020-05-01 16:42:56',0),(8,10,1,'2020-11-21 22:14:13',0),(9,1,2,'2020-11-22 20:49:47',0),(10,10,2,'2020-11-22 20:49:47',0),(11,6,2,'2020-11-22 20:49:47',0);
/*!40000 ALTER TABLE `members` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `messages`
--

DROP TABLE IF EXISTS `messages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `messages` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `board_id` int(11) NOT NULL,
  `parent_id` int(11) DEFAULT NULL,
  `subject` varchar(255) NOT NULL DEFAULT '',
  `content` text,
  `author_id` int(11) DEFAULT NULL,
  `replies_count` int(11) NOT NULL DEFAULT '0',
  `last_reply_id` int(11) DEFAULT NULL,
  `created_on` datetime NOT NULL,
  `updated_on` datetime NOT NULL,
  `locked` tinyint(1) DEFAULT '0',
  `sticky` int(11) DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `messages_board_id` (`board_id`),
  KEY `messages_parent_id` (`parent_id`),
  KEY `index_messages_on_last_reply_id` (`last_reply_id`),
  KEY `index_messages_on_author_id` (`author_id`),
  KEY `index_messages_on_created_on` (`created_on`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `messages`
--

LOCK TABLES `messages` WRITE;
/*!40000 ALTER TABLE `messages` DISABLE KEYS */;
/*!40000 ALTER TABLE `messages` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `news`
--

DROP TABLE IF EXISTS `news`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `news` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `project_id` int(11) DEFAULT NULL,
  `title` varchar(60) NOT NULL DEFAULT '',
  `summary` varchar(255) DEFAULT '',
  `description` text,
  `author_id` int(11) NOT NULL DEFAULT '0',
  `created_on` timestamp NULL DEFAULT NULL,
  `comments_count` int(11) NOT NULL DEFAULT '0',
  PRIMARY KEY (`id`),
  KEY `news_project_id` (`project_id`),
  KEY `index_news_on_author_id` (`author_id`),
  KEY `index_news_on_created_on` (`created_on`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `news`
--

LOCK TABLES `news` WRITE;
/*!40000 ALTER TABLE `news` DISABLE KEYS */;
/*!40000 ALTER TABLE `news` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `open_id_authentication_associations`
--

DROP TABLE IF EXISTS `open_id_authentication_associations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `open_id_authentication_associations` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `issued` int(11) DEFAULT NULL,
  `lifetime` int(11) DEFAULT NULL,
  `handle` varchar(255) DEFAULT NULL,
  `assoc_type` varchar(255) DEFAULT NULL,
  `server_url` blob,
  `secret` blob,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `open_id_authentication_associations`
--

LOCK TABLES `open_id_authentication_associations` WRITE;
/*!40000 ALTER TABLE `open_id_authentication_associations` DISABLE KEYS */;
/*!40000 ALTER TABLE `open_id_authentication_associations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `open_id_authentication_nonces`
--

DROP TABLE IF EXISTS `open_id_authentication_nonces`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `open_id_authentication_nonces` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `timestamp` int(11) NOT NULL,
  `server_url` varchar(255) DEFAULT NULL,
  `salt` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `open_id_authentication_nonces`
--

LOCK TABLES `open_id_authentication_nonces` WRITE;
/*!40000 ALTER TABLE `open_id_authentication_nonces` DISABLE KEYS */;
/*!40000 ALTER TABLE `open_id_authentication_nonces` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `projects`
--

DROP TABLE IF EXISTS `projects`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `projects` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL DEFAULT '',
  `description` text,
  `homepage` varchar(255) DEFAULT '',
  `is_public` tinyint(1) NOT NULL DEFAULT '1',
  `parent_id` int(11) DEFAULT NULL,
  `created_on` timestamp NULL DEFAULT NULL,
  `updated_on` timestamp NULL DEFAULT NULL,
  `identifier` varchar(255) DEFAULT NULL,
  `status` int(11) NOT NULL DEFAULT '1',
  `lft` int(11) DEFAULT NULL,
  `rgt` int(11) DEFAULT NULL,
  `inherit_members` tinyint(1) NOT NULL DEFAULT '0',
  `default_version_id` int(11) DEFAULT NULL,
  `default_assigned_to_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `index_projects_on_lft` (`lft`),
  KEY `index_projects_on_rgt` (`rgt`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `projects`
--

LOCK TABLES `projects` WRITE;
/*!40000 ALTER TABLE `projects` DISABLE KEYS */;
INSERT INTO `projects` VALUES (1,'Detection Playbooks','','',1,NULL,'2020-04-26 13:13:01','2020-07-10 19:33:53','detection-playbooks',1,1,2,0,NULL,NULL),(2,'Options','','',1,NULL,'2020-11-22 20:49:17','2020-11-22 20:49:17','options',1,3,4,0,NULL,NULL);
/*!40000 ALTER TABLE `projects` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `projects_trackers`
--

DROP TABLE IF EXISTS `projects_trackers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `projects_trackers` (
  `project_id` int(11) NOT NULL DEFAULT '0',
  `tracker_id` int(11) NOT NULL DEFAULT '0',
  UNIQUE KEY `projects_trackers_unique` (`project_id`,`tracker_id`),
  KEY `projects_trackers_project_id` (`project_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `projects_trackers`
--

LOCK TABLES `projects_trackers` WRITE;
/*!40000 ALTER TABLE `projects_trackers` DISABLE KEYS */;
INSERT INTO `projects_trackers` VALUES (1,1),(2,2),(2,3);
/*!40000 ALTER TABLE `projects_trackers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `queries`
--

DROP TABLE IF EXISTS `queries`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `queries` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `project_id` int(11) DEFAULT NULL,
  `name` varchar(255) NOT NULL DEFAULT '',
  `filters` text,
  `user_id` int(11) NOT NULL DEFAULT '0',
  `column_names` text,
  `sort_criteria` text,
  `group_by` varchar(255) DEFAULT NULL,
  `type` varchar(255) DEFAULT NULL,
  `visibility` int(11) DEFAULT '0',
  `options` text,
  PRIMARY KEY (`id`),
  KEY `index_queries_on_project_id` (`project_id`),
  KEY `index_queries_on_user_id` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=10 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `queries`
--

LOCK TABLES `queries` WRITE;
/*!40000 ALTER TABLE `queries` DISABLE KEYS */;
INSERT INTO `queries` VALUES (3,1,'All Plays','---\ntracker_id:\n  :operator: \"=\"\n  :values:\n  - \'1\'\n',1,NULL,'---\n- - id\n  - desc\n','','IssueQuery',2,'---\n:totalable_names: []\n:display_type: list\n:draw_relations: \n:draw_progress_line: \n:draw_selected_columns: \n'),(4,NULL,'Inactive Plays','---\nstatus_id:\n  :operator: \"=\"\n  :values:\n  - \'4\'\n',1,NULL,'---\n- - id\n  - desc\n','','IssueQuery',2,'---\n:totalable_names: []\n:display_type: list\n:draw_relations: \n:draw_progress_line: \n:draw_selected_columns: \n'),(5,NULL,'Draft Plays','---\nstatus_id:\n  :operator: \"=\"\n  :values:\n  - \'2\'\n',1,NULL,'---\n- - id\n  - desc\n','','IssueQuery',2,'---\n:totalable_names: []\n:display_type: list\n:draw_relations: \n:draw_progress_line: \n:draw_selected_columns: \n'),(6,NULL,'Playbook - Community Sigma','---\ncf_13:\n  :operator: \"=\"\n  :values:\n  - community\n',1,'---\n- :status\n- :cf_10\n- :cf_18\n- :cf_19\n- :cf_20\n- :cf_1\n- :updated_on\n','---\n- - id\n  - desc\n','','IssueQuery',2,'---\n:totalable_names: []\n:display_type: list\n:draw_relations: \n:draw_progress_line: \n:draw_selected_columns: \n'),(8,NULL,'Playbook - Internal','---\ncf_13:\n  :operator: \"=\"\n  :values:\n  - Internal\n',1,'---\n- :status\n- :cf_10\n- :cf_14\n- :cf_16\n- :cf_1\n- :updated_on\n','---\n- - id\n  - desc\n','','IssueQuery',2,'---\n:totalable_names: []\n:display_type: list\n:draw_relations: \n:draw_progress_line: \n:draw_selected_columns: \n'),(9,NULL,'Active Plays','---\ntracker_id:\n  :operator: \"=\"\n  :values:\n  - \'1\'\nstatus_id:\n  :operator: \"=\"\n  :values:\n  - \'3\'\n',1,'---\n- :status\n- :cf_10\n- :cf_13\n- :cf_18\n- :cf_19\n- :cf_1\n- :updated_on\n','---\n- - id\n  - desc\n','','IssueQuery',2,'---\n:totalable_names: []\n:display_type: list\n:draw_relations: \n:draw_progress_line: \n:draw_selected_columns: \n');
/*!40000 ALTER TABLE `queries` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `queries_roles`
--

DROP TABLE IF EXISTS `queries_roles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `queries_roles` (
  `query_id` int(11) NOT NULL,
  `role_id` int(11) NOT NULL,
  UNIQUE KEY `queries_roles_ids` (`query_id`,`role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `queries_roles`
--

LOCK TABLES `queries_roles` WRITE;
/*!40000 ALTER TABLE `queries_roles` DISABLE KEYS */;
/*!40000 ALTER TABLE `queries_roles` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `repositories`
--

DROP TABLE IF EXISTS `repositories`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `repositories` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `project_id` int(11) NOT NULL DEFAULT '0',
  `url` varchar(255) NOT NULL DEFAULT '',
  `login` varchar(60) DEFAULT '',
  `password` varchar(255) DEFAULT '',
  `root_url` varchar(255) DEFAULT '',
  `type` varchar(255) DEFAULT NULL,
  `path_encoding` varchar(64) DEFAULT NULL,
  `log_encoding` varchar(64) DEFAULT NULL,
  `extra_info` longtext,
  `identifier` varchar(255) DEFAULT NULL,
  `is_default` tinyint(1) DEFAULT '0',
  `created_on` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `index_repositories_on_project_id` (`project_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `repositories`
--

LOCK TABLES `repositories` WRITE;
/*!40000 ALTER TABLE `repositories` DISABLE KEYS */;
/*!40000 ALTER TABLE `repositories` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `roles`
--

DROP TABLE IF EXISTS `roles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `roles` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL DEFAULT '',
  `position` int(11) DEFAULT NULL,
  `assignable` tinyint(1) DEFAULT '1',
  `builtin` int(11) NOT NULL DEFAULT '0',
  `permissions` text,
  `issues_visibility` varchar(30) NOT NULL DEFAULT 'default',
  `users_visibility` varchar(30) NOT NULL DEFAULT 'all',
  `time_entries_visibility` varchar(30) NOT NULL DEFAULT 'all',
  `all_roles_managed` tinyint(1) NOT NULL DEFAULT '1',
  `settings` text,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `roles`
--

LOCK TABLES `roles` WRITE;
/*!40000 ALTER TABLE `roles` DISABLE KEYS */;
INSERT INTO `roles` VALUES (1,'Non member',0,1,1,NULL,'default','all','all',1,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\npermissions_all_trackers: !ruby/hash:ActiveSupport::HashWithIndifferentAccess\n  view_issues: \'0\'\n  add_issues: \'1\'\n  edit_issues: \'1\'\n  add_issue_notes: \'1\'\npermissions_tracker_ids: !ruby/hash:ActiveSupport::HashWithIndifferentAccess\n  view_issues: []\n  add_issues: []\n  edit_issues: []\n  add_issue_notes: []\n'),(2,'Anonymous',0,1,2,'---\n- :view_issues\n- :edit_issues\n- :add_issue_notes\n- :sigma_editor\n','default','all','all',1,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\npermissions_all_trackers: !ruby/hash:ActiveSupport::HashWithIndifferentAccess\n  view_issues: \'1\'\n  add_issues: \'1\'\n  edit_issues: \'1\'\n  add_issue_notes: \'1\'\npermissions_tracker_ids: !ruby/hash:ActiveSupport::HashWithIndifferentAccess\n  view_issues: []\n  add_issues: []\n  edit_issues: []\n  add_issue_notes: []\n'),(3,'Security-Analyst',1,0,0,'---\n- :save_queries\n- :view_issues\n- :edit_issues\n- :add_issue_notes\n- :edit_issue_notes\n- :sigma_editor\n','all','all','all',1,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\npermissions_all_trackers: !ruby/hash:ActiveSupport::HashWithIndifferentAccess\n  view_issues: \'1\'\n  add_issues: \'1\'\n  edit_issues: \'1\'\n  add_issue_notes: \'1\'\n  delete_issues: \'1\'\npermissions_tracker_ids: !ruby/hash:ActiveSupport::HashWithIndifferentAccess\n  view_issues: []\n  add_issues: []\n  edit_issues: []\n  add_issue_notes: []\n  delete_issues: []\n'),(4,'SuperAdmin',2,0,0,'---\n- :add_project\n- :edit_project\n- :close_project\n- :select_project_modules\n- :manage_members\n- :manage_versions\n- :add_subprojects\n- :manage_public_queries\n- :save_queries\n- :manage_hook\n- :view_messages\n- :add_messages\n- :edit_messages\n- :edit_own_messages\n- :delete_messages\n- :delete_own_messages\n- :manage_boards\n- :view_calendar\n- :view_documents\n- :add_documents\n- :edit_documents\n- :delete_documents\n- :view_files\n- :manage_files\n- :view_gantt\n- :view_issues\n- :edit_issues\n- :edit_own_issues\n- :copy_issues\n- :manage_issue_relations\n- :manage_subtasks\n- :set_issues_private\n- :set_own_issues_private\n- :add_issue_notes\n- :edit_issue_notes\n- :edit_own_issue_notes\n- :view_private_notes\n- :set_notes_private\n- :delete_issues\n- :view_issue_watchers\n- :add_issue_watchers\n- :delete_issue_watchers\n- :import_issues\n- :manage_categories\n- :view_news\n- :manage_news\n- :comment_news\n- :view_changesets\n- :browse_repository\n- :commit_access\n- :manage_related_issues\n- :manage_repository\n- :sigma_editor\n- :view_time_entries\n- :log_time\n- :edit_time_entries\n- :edit_own_time_entries\n- :manage_project_activities\n- :log_time_for_other_users\n- :import_time_entries\n- :view_wiki_pages\n- :view_wiki_edits\n- :export_wiki_pages\n- :edit_wiki_pages\n- :rename_wiki_pages\n- :delete_wiki_pages\n- :delete_wiki_pages_attachments\n- :protect_wiki_pages\n- :manage_wiki\n','default','all','all',1,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\npermissions_all_trackers: !ruby/hash:ActiveSupport::HashWithIndifferentAccess\n  view_issues: \'1\'\n  add_issues: \'1\'\n  edit_issues: \'1\'\n  add_issue_notes: \'1\'\n  delete_issues: \'1\'\npermissions_tracker_ids: !ruby/hash:ActiveSupport::HashWithIndifferentAccess\n  view_issues: []\n  add_issues: []\n  edit_issues: []\n  add_issue_notes: []\n  delete_issues: []\n'),(5,'Automation',3,0,0,'---\n- :view_issues\n- :add_issues\n- :edit_issues\n- :add_issue_notes\n- :edit_issue_notes\n- :import_issues\n- :sigma_editor\n','default','all','all',1,'--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\npermissions_all_trackers: !ruby/hash:ActiveSupport::HashWithIndifferentAccess\n  view_issues: \'1\'\n  add_issues: \'1\'\n  edit_issues: \'1\'\n  add_issue_notes: \'1\'\n  delete_issues: \'1\'\npermissions_tracker_ids: !ruby/hash:ActiveSupport::HashWithIndifferentAccess\n  view_issues: []\n  add_issues: []\n  edit_issues: []\n  add_issue_notes: []\n  delete_issues: []\n');
/*!40000 ALTER TABLE `roles` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `roles_managed_roles`
--

DROP TABLE IF EXISTS `roles_managed_roles`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `roles_managed_roles` (
  `role_id` int(11) NOT NULL,
  `managed_role_id` int(11) NOT NULL,
  UNIQUE KEY `index_roles_managed_roles_on_role_id_and_managed_role_id` (`role_id`,`managed_role_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `roles_managed_roles`
--

LOCK TABLES `roles_managed_roles` WRITE;
/*!40000 ALTER TABLE `roles_managed_roles` DISABLE KEYS */;
/*!40000 ALTER TABLE `roles_managed_roles` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `schema_migrations`
--

DROP TABLE IF EXISTS `schema_migrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `schema_migrations` (
  `version` varchar(255) NOT NULL,
  PRIMARY KEY (`version`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `schema_migrations`
--

LOCK TABLES `schema_migrations` WRITE;
/*!40000 ALTER TABLE `schema_migrations` DISABLE KEYS */;
INSERT INTO `schema_migrations` VALUES ('1'),('1-redmine_webhook'),('10'),('100'),('101'),('102'),('103'),('104'),('105'),('106'),('107'),('108'),('11'),('12'),('13'),('14'),('15'),('16'),('17'),('18'),('19'),('2'),('20'),('20090214190337'),('20090312172426'),('20090312194159'),('20090318181151'),('20090323224724'),('20090401221305'),('20090401231134'),('20090403001910'),('20090406161854'),('20090425161243'),('20090503121501'),('20090503121505'),('20090503121510'),('20090614091200'),('20090704172350'),('20090704172355'),('20090704172358'),('20091010093521'),('20091017212227'),('20091017212457'),('20091017212644'),('20091017212938'),('20091017213027'),('20091017213113'),('20091017213151'),('20091017213228'),('20091017213257'),('20091017213332'),('20091017213444'),('20091017213536'),('20091017213642'),('20091017213716'),('20091017213757'),('20091017213835'),('20091017213910'),('20091017214015'),('20091017214107'),('20091017214136'),('20091017214236'),('20091017214308'),('20091017214336'),('20091017214406'),('20091017214440'),('20091017214519'),('20091017214611'),('20091017214644'),('20091017214720'),('20091017214750'),('20091025163651'),('20091108092559'),('20091114105931'),('20091123212029'),('20091205124427'),('20091220183509'),('20091220183727'),('20091220184736'),('20091225164732'),('20091227112908'),('20100129193402'),('20100129193813'),('20100221100219'),('20100313132032'),('20100313171051'),('20100705164950'),('20100819172912'),('20101104182107'),('20101107130441'),('20101114115114'),('20101114115359'),('20110220160626'),('20110223180944'),('20110223180953'),('20110224000000'),('20110226120112'),('20110226120132'),('20110227125750'),('20110228000000'),('20110228000100'),('20110401192910'),('20110408103312'),('20110412065600'),('20110511000000'),('20110902000000'),('20111201201315'),('20120115143024'),('20120115143100'),('20120115143126'),('20120127174243'),('20120205111326'),('20120223110929'),('20120301153455'),('20120422150750'),('20120705074331'),('20120707064544'),('20120714122000'),('20120714122100'),('20120714122200'),('20120731164049'),('20120930112914'),('20121026002032'),('20121026003537'),('20121209123234'),('20121209123358'),('20121213084931'),('20130110122628'),('20130201184705'),('20130202090625'),('20130207175206'),('20130207181455'),('20130215073721'),('20130215111127'),('20130215111141'),('20130217094251'),('20130602092539'),('20130710182539'),('20130713104233'),('20130713111657'),('20130729070143'),('20130911193200'),('20131004113137'),('20131005100610'),('20131124175346'),('20131210180802'),('20131214094309'),('20131215104612'),('20131218183023'),('20140228130325'),('20140903143914'),('20140920094058'),('20141029181752'),('20141029181824'),('20141109112308'),('20141122124142'),('20150113194759'),('20150113211532'),('20150113213922'),('20150113213955'),('20150208105930'),('20150510083747'),('20150525103953'),('20150526183158'),('20150528084820'),('20150528092912'),('20150528093249'),('20150725112753'),('20150730122707'),('20150730122735'),('20150921204850'),('20150921210243'),('20151020182334'),('20151020182731'),('20151021184614'),('20151021185456'),('20151021190616'),('20151024082034'),('20151025072118'),('20151031095005'),('20160404080304'),('20160416072926'),('20160529063352'),('20161001122012'),('20161002133421'),('20161010081301'),('20161010081528'),('20161010081600'),('20161126094932'),('20161220091118'),('20170207050700'),('20170302015225'),('20170309214320'),('20170320051650'),('20170418090031'),('20170419144536'),('20170723112801'),('20180501132547'),('20180913072918'),('20180923082945'),('20180923091603'),('20190315094151'),('20190315102101'),('20190510070108'),('20190620135549'),('21'),('22'),('23'),('24'),('25'),('26'),('27'),('28'),('29'),('3'),('30'),('31'),('32'),('33'),('34'),('35'),('36'),('37'),('38'),('39'),('4'),('40'),('41'),('42'),('43'),('44'),('45'),('46'),('47'),('48'),('49'),('5'),('50'),('51'),('52'),('53'),('54'),('55'),('56'),('57'),('58'),('59'),('6'),('60'),('61'),('62'),('63'),('64'),('65'),('66'),('67'),('68'),('69'),('7'),('70'),('71'),('72'),('73'),('74'),('75'),('76'),('77'),('78'),('79'),('8'),('80'),('81'),('82'),('83'),('84'),('85'),('86'),('87'),('88'),('89'),('9'),('90'),('91'),('92'),('93'),('94'),('95'),('96'),('97'),('98'),('99');
/*!40000 ALTER TABLE `schema_migrations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `settings`
--

DROP TABLE IF EXISTS `settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `settings` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL DEFAULT '',
  `value` text,
  `updated_on` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `index_settings_on_name` (`name`)
) ENGINE=InnoDB AUTO_INCREMENT=71 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `settings`
--

LOCK TABLES `settings` WRITE;
/*!40000 ALTER TABLE `settings` DISABLE KEYS */;
INSERT INTO `settings` VALUES (1,'ui_theme','circle','2020-04-26 13:11:26'),(2,'default_language','en','2020-04-26 13:11:26'),(3,'force_default_language_for_anonymous','0','2020-04-26 13:11:26'),(4,'force_default_language_for_loggedin','0','2020-04-26 13:11:26'),(5,'start_of_week','','2020-04-26 13:11:26'),(6,'date_format','','2020-04-26 13:11:26'),(7,'time_format','','2020-04-26 13:11:26'),(8,'timespan_format','decimal','2020-04-26 13:11:26'),(9,'user_format','firstname_lastname','2020-05-02 12:45:00'),(10,'gravatar_enabled','1','2020-05-02 12:41:07'),(11,'thumbnails_enabled','1','2020-04-26 13:11:26'),(12,'thumbnails_size','100','2020-04-26 13:11:26'),(13,'new_item_menu_tab','0','2020-04-26 13:11:30'),(14,'login_required','0','2020-07-10 19:32:45'),(15,'autologin','0','2020-04-26 13:11:54'),(16,'self_registration','0','2020-04-26 13:11:54'),(17,'show_custom_fields_on_registration','0','2020-04-26 13:11:54'),(18,'password_min_length','8','2020-04-26 13:11:54'),(19,'password_required_char_classes','--- []\n','2020-04-26 13:11:54'),(20,'password_max_age','0','2020-04-26 13:11:54'),(21,'lost_password','1','2020-04-26 13:11:54'),(22,'openid','0','2020-04-26 13:11:55'),(23,'session_lifetime','0','2020-04-26 13:11:55'),(24,'session_timeout','0','2020-04-26 13:11:55'),(25,'rest_api_enabled','1','2020-04-26 13:11:58'),(26,'jsonp_enabled','0','2020-04-26 13:11:58'),(27,'default_projects_public','0','2020-04-26 13:12:21'),(28,'default_projects_modules','---\n- sigma_editor\n','2020-04-26 13:12:21'),(29,'default_projects_tracker_ids','--- []\n','2020-04-26 13:12:21'),(30,'sequential_project_identifiers','0','2020-04-26 13:12:21'),(31,'project_list_defaults','---\n:column_names:\n- name\n- identifier\n- short_description\n','2020-04-26 13:12:21'),(32,'app_title','Playbook','2020-04-26 18:17:51'),(33,'welcome_text','','2020-04-26 18:17:51'),(34,'per_page_options','25,75,150','2020-05-02 12:41:38'),(35,'search_results_per_page','10','2020-04-26 18:17:51'),(36,'activity_days_default','30','2020-04-26 18:17:51'),(37,'host_name','localhost:3000','2020-04-26 18:17:51'),(38,'protocol','http','2020-04-26 18:17:51'),(39,'text_formatting','textile','2020-04-26 18:17:51'),(40,'cache_formatted_text','0','2020-04-26 18:17:51'),(41,'wiki_compression','','2020-04-26 18:17:51'),(42,'feeds_limit','15','2020-04-26 18:17:51'),(43,'plugin_redmine_playbook','--- !ruby/hash:ActiveSupport::HashWithIndifferentAccess\nproject: \'1\'\nconvert_url: http://10.66.166.121:7000/playbook/sigmac\ncreate_url: http://10.66.166.121:7000/playbook/play','2020-05-02 12:39:20'),(44,'cross_project_issue_relations','0','2020-05-01 16:27:33'),(45,'link_copied_issue','no','2020-05-01 16:27:33'),(46,'cross_project_subtasks','','2020-05-01 16:27:33'),(47,'close_duplicate_issues','0','2020-05-01 16:27:33'),(48,'issue_group_assignment','0','2020-05-01 16:27:33'),(49,'default_issue_start_date_to_creation_date','1','2020-05-01 16:27:33'),(50,'display_subprojects_issues','0','2020-05-01 16:27:33'),(51,'issue_done_ratio','issue_field','2020-05-01 16:27:33'),(52,'non_working_week_days','---\n- \'6\'\n- \'7\'\n','2020-05-01 16:27:33'),(53,'issues_export_limit','500','2020-05-01 16:27:33'),(54,'gantt_items_limit','500','2020-05-01 16:27:33'),(55,'gantt_months_limit','24','2020-05-01 16:27:33'),(56,'parent_issue_dates','derived','2020-05-01 16:27:33'),(57,'parent_issue_priority','derived','2020-05-01 16:27:33'),(58,'parent_issue_done_ratio','derived','2020-05-01 16:27:33'),(59,'issue_list_default_columns','---\n- status\n- cf_10\n- cf_13\n- cf_14\n- cf_1\n- updated_on\n','2020-05-01 19:32:13'),(60,'issue_list_default_totals','--- []\n','2020-05-01 16:27:33'),(61,'enabled_scm','--- []\n','2020-05-01 16:27:47'),(62,'autofetch_changesets','0','2020-05-01 16:27:47'),(63,'sys_api_enabled','0','2020-05-01 16:27:47'),(64,'repository_log_display_limit','100','2020-05-01 16:27:47'),(65,'commit_logs_formatting','1','2020-05-01 16:27:47'),(66,'commit_ref_keywords','refs,references,IssueID','2020-05-01 16:27:47'),(67,'commit_cross_project_ref','0','2020-05-01 16:27:47'),(68,'commit_logtime_enabled','0','2020-05-01 16:27:47'),(69,'commit_update_keywords','--- []\n','2020-05-01 16:27:47'),(70,'gravatar_default','','2020-05-02 12:41:07');
/*!40000 ALTER TABLE `settings` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `time_entries`
--

DROP TABLE IF EXISTS `time_entries`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `time_entries` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `project_id` int(11) NOT NULL,
  `author_id` int(11) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  `issue_id` int(11) DEFAULT NULL,
  `hours` float NOT NULL,
  `comments` varchar(1024) DEFAULT NULL,
  `activity_id` int(11) NOT NULL,
  `spent_on` date NOT NULL,
  `tyear` int(11) NOT NULL,
  `tmonth` int(11) NOT NULL,
  `tweek` int(11) NOT NULL,
  `created_on` datetime NOT NULL,
  `updated_on` datetime NOT NULL,
  PRIMARY KEY (`id`),
  KEY `time_entries_project_id` (`project_id`),
  KEY `time_entries_issue_id` (`issue_id`),
  KEY `index_time_entries_on_activity_id` (`activity_id`),
  KEY `index_time_entries_on_user_id` (`user_id`),
  KEY `index_time_entries_on_created_on` (`created_on`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `time_entries`
--

LOCK TABLES `time_entries` WRITE;
/*!40000 ALTER TABLE `time_entries` DISABLE KEYS */;
/*!40000 ALTER TABLE `time_entries` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `tokens`
--

DROP TABLE IF EXISTS `tokens`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `tokens` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL DEFAULT '0',
  `action` varchar(30) NOT NULL DEFAULT '',
  `value` varchar(40) NOT NULL DEFAULT '',
  `created_on` datetime NOT NULL,
  `updated_on` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `tokens_value` (`value`),
  KEY `index_tokens_on_user_id` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=72 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `tokens`
--

LOCK TABLES `tokens` WRITE;
/*!40000 ALTER TABLE `tokens` DISABLE KEYS */;
INSERT INTO `tokens` VALUES (3,1,'feeds','6e5575602e1227c188cd85ef6d12608bb8701193','2020-04-26 13:10:46','2020-04-26 13:10:46'),(4,1,'session','999412fa9badda7423c6c654d6364c32c20b3eac','2020-04-26 18:07:03','2020-04-26 18:12:02'),(5,1,'session','124ad4acbf87a942426350e7ad028c1d119c3851','2020-04-26 18:17:11','2020-04-26 18:19:24'),(9,1,'session','2890c663e0552f26ddb92acad6ab3b6d05b92915','2020-04-26 18:51:15','2020-04-26 18:51:15'),(19,1,'session','b7ffb106ea0b34650dd9c1770f74c2b0ffe166b2','2020-05-01 16:52:33','2020-05-01 18:02:30'),(20,1,'session','f44cfcf918eef59ffda47991c431d9c2b2ac6113','2020-05-01 18:05:56','2020-05-01 18:05:56'),(23,9,'feeds','211918c9d7168979b5dc19bebb14573b928a5067','2020-05-01 18:26:17','2020-05-01 18:26:17'),(46,1,'session','2d0c8f8ae641c06d8c2362746846440d465d53c0','2020-05-06 20:48:01','2020-05-06 20:48:07'),(59,1,'session','2afe6590653d59a697d1436729c64f322a2eff82','2020-07-01 18:11:07','2020-07-01 20:30:43'),(61,1,'session','b01f95709ca1ab086a049cf9c5afd81ca9d4526e','2020-07-15 16:30:42','2020-07-15 16:31:40'),(62,1,'session','d29acdcd0b8e4ebf78ef8f696d3e76df7e2ab2ac','2020-08-17 14:51:59','2020-08-17 14:53:22'),(67,10,'api','a92a42f4fbbb23e713adc4f57091129457f6acfe','2020-11-21 22:14:13','2020-11-21 22:14:13'),(71,1,'session','3bcc8d4d9b8a5dda138da6f2f346bb2503b1ec9d','2020-12-08 03:01:36','2020-12-08 03:02:48');
/*!40000 ALTER TABLE `tokens` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `trackers`
--

DROP TABLE IF EXISTS `trackers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `trackers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(30) NOT NULL DEFAULT '',
  `description` varchar(255) DEFAULT NULL,
  `is_in_chlog` tinyint(1) NOT NULL DEFAULT '0',
  `position` int(11) DEFAULT NULL,
  `is_in_roadmap` tinyint(1) NOT NULL DEFAULT '1',
  `fields_bits` int(11) DEFAULT '0',
  `default_status_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `trackers`
--

LOCK TABLES `trackers` WRITE;
/*!40000 ALTER TABLE `trackers` DISABLE KEYS */;
INSERT INTO `trackers` VALUES (1,'Play','',0,1,0,255,2),(2,'Email Options','',0,2,1,511,2),(3,'Sigma Options','',0,3,1,511,2);
/*!40000 ALTER TABLE `trackers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `user_preferences`
--

DROP TABLE IF EXISTS `user_preferences`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `user_preferences` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL DEFAULT '0',
  `others` text,
  `hide_mail` tinyint(1) DEFAULT '1',
  `time_zone` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `index_user_preferences_on_user_id` (`user_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `user_preferences`
--

LOCK TABLES `user_preferences` WRITE;
/*!40000 ALTER TABLE `user_preferences` DISABLE KEYS */;
INSERT INTO `user_preferences` VALUES (1,1,'---\n:no_self_notified: \'1\'\n:my_page_layout:\n  left:\n  - issuesassignedtome\n  right:\n  - issuesreportedbyme\n:my_page_settings: {}\n:comments_sorting: asc\n:warn_on_leaving_unsaved: \'1\'\n:textarea_font: \'\'\n:recently_used_projects: 3\n:history_default_tab: notes\n:recently_used_project_ids: \'1,2\'\n',1,''),(3,9,'---\n:no_self_notified: \'1\'\n:comments_sorting: asc\n:warn_on_leaving_unsaved: \'1\'\n:textarea_font: \'\'\n:recently_used_projects: 3\n:history_default_tab: notes\n:my_page_layout:\n  left:\n  - issuesassignedtome\n  right:\n  - issuesreportedbyme\n:my_page_settings: {}\n:recently_used_project_ids: \'1\'\n',1,''),(4,10,'---\n:no_self_notified: true\n:my_page_layout:\n  left:\n  - issuesassignedtome\n  right:\n  - issuesreportedbyme\n:my_page_settings: {}\n:recently_used_project_ids: \'1\'\n',1,'');
/*!40000 ALTER TABLE `user_preferences` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `login` varchar(255) NOT NULL DEFAULT '',
  `hashed_password` varchar(40) NOT NULL DEFAULT '',
  `firstname` varchar(30) NOT NULL DEFAULT '',
  `lastname` varchar(255) NOT NULL DEFAULT '',
  `admin` tinyint(1) NOT NULL DEFAULT '0',
  `status` int(11) NOT NULL DEFAULT '1',
  `last_login_on` datetime DEFAULT NULL,
  `language` varchar(5) DEFAULT '',
  `auth_source_id` int(11) DEFAULT NULL,
  `created_on` timestamp NULL DEFAULT NULL,
  `updated_on` timestamp NULL DEFAULT NULL,
  `type` varchar(255) DEFAULT NULL,
  `identity_url` varchar(255) DEFAULT NULL,
  `mail_notification` varchar(255) NOT NULL DEFAULT '',
  `salt` varchar(64) DEFAULT NULL,
  `must_change_passwd` tinyint(1) NOT NULL DEFAULT '0',
  `passwd_changed_on` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `index_users_on_id_and_type` (`id`,`type`),
  KEY `index_users_on_auth_source_id` (`auth_source_id`),
  KEY `index_users_on_type` (`type`)
) ENGINE=InnoDB AUTO_INCREMENT=11 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'admin','27193748a2fc174c339e7c22292bccb882f6f756','Admin','Admin',1,1,'2020-12-08 03:01:36','',NULL,'2020-04-26 13:08:34','2020-04-26 13:10:45','User',NULL,'all','5exVbsSixI1ub0aOGSRyctmB4EMwk7v2',0,'2020-04-26 13:10:27'),(2,'','','','Anonymous users',0,1,NULL,'',NULL,'2020-04-26 13:08:38','2020-04-26 13:08:38','GroupAnonymous',NULL,'',NULL,0,NULL),(3,'','','','Non member users',0,1,NULL,'',NULL,'2020-04-26 13:08:38','2020-04-26 13:08:38','GroupNonMember',NULL,'',NULL,0,NULL),(4,'','','','Anonymous',0,0,NULL,'',NULL,'2020-04-26 13:09:44','2020-04-26 13:09:44','AnonymousUser',NULL,'only_my_events',NULL,0,NULL),(5,'','','','Analysts',0,1,NULL,'',NULL,'2020-04-26 18:43:40','2020-04-26 18:43:40','Group',NULL,'',NULL,0,NULL),(6,'','','','Automation',0,1,NULL,'',NULL,'2020-04-26 18:43:47','2020-04-26 18:43:47','Group',NULL,'',NULL,0,NULL),(7,'','','','Admins',0,1,NULL,'',NULL,'2020-04-26 18:43:58','2020-04-26 18:43:58','Group',NULL,'',NULL,0,NULL),(10,'automation','05af6545acc48ea85bf4b002e560b702b727c9f8','SecOps','Automation',0,1,NULL,'en',NULL,'2020-11-21 22:14:13','2020-11-21 22:14:13','User',NULL,'only_my_events','8e99dd319cef62d18e80bb9f29cc1ce8',0,'2020-11-21 22:14:13');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `versions`
--

DROP TABLE IF EXISTS `versions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `versions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `project_id` int(11) NOT NULL DEFAULT '0',
  `name` varchar(255) NOT NULL DEFAULT '',
  `description` varchar(255) DEFAULT '',
  `effective_date` date DEFAULT NULL,
  `created_on` timestamp NULL DEFAULT NULL,
  `updated_on` timestamp NULL DEFAULT NULL,
  `wiki_page_title` varchar(255) DEFAULT NULL,
  `status` varchar(255) DEFAULT 'open',
  `sharing` varchar(255) NOT NULL DEFAULT 'none',
  PRIMARY KEY (`id`),
  KEY `versions_project_id` (`project_id`),
  KEY `index_versions_on_sharing` (`sharing`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `versions`
--

LOCK TABLES `versions` WRITE;
/*!40000 ALTER TABLE `versions` DISABLE KEYS */;
/*!40000 ALTER TABLE `versions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `watchers`
--

DROP TABLE IF EXISTS `watchers`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `watchers` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `watchable_type` varchar(255) NOT NULL DEFAULT '',
  `watchable_id` int(11) NOT NULL DEFAULT '0',
  `user_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `watchers_user_id_type` (`user_id`,`watchable_type`),
  KEY `index_watchers_on_user_id` (`user_id`),
  KEY `index_watchers_on_watchable_id_and_watchable_type` (`watchable_id`,`watchable_type`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `watchers`
--

LOCK TABLES `watchers` WRITE;
/*!40000 ALTER TABLE `watchers` DISABLE KEYS */;
/*!40000 ALTER TABLE `watchers` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `webhooks`
--

DROP TABLE IF EXISTS `webhooks`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `webhooks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `url` varchar(255) DEFAULT NULL,
  `project_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `webhooks`
--

LOCK TABLES `webhooks` WRITE;
/*!40000 ALTER TABLE `webhooks` DISABLE KEYS */;
INSERT INTO `webhooks` VALUES (1,'http://10.66.166.121:7000/playbook/webhook',1),(2,'http://10.66.166.121:7000/playbook/webhook',2);
/*!40000 ALTER TABLE `webhooks` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `wiki_content_versions`
--

DROP TABLE IF EXISTS `wiki_content_versions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `wiki_content_versions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `wiki_content_id` int(11) NOT NULL,
  `page_id` int(11) NOT NULL,
  `author_id` int(11) DEFAULT NULL,
  `data` longblob,
  `compression` varchar(6) DEFAULT '',
  `comments` varchar(1024) DEFAULT '',
  `updated_on` datetime NOT NULL,
  `version` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `wiki_content_versions_wcid` (`wiki_content_id`),
  KEY `index_wiki_content_versions_on_updated_on` (`updated_on`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `wiki_content_versions`
--

LOCK TABLES `wiki_content_versions` WRITE;
/*!40000 ALTER TABLE `wiki_content_versions` DISABLE KEYS */;
/*!40000 ALTER TABLE `wiki_content_versions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `wiki_contents`
--

DROP TABLE IF EXISTS `wiki_contents`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `wiki_contents` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `page_id` int(11) NOT NULL,
  `author_id` int(11) DEFAULT NULL,
  `text` longtext,
  `comments` varchar(1024) DEFAULT '',
  `updated_on` datetime NOT NULL,
  `version` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `wiki_contents_page_id` (`page_id`),
  KEY `index_wiki_contents_on_author_id` (`author_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `wiki_contents`
--

LOCK TABLES `wiki_contents` WRITE;
/*!40000 ALTER TABLE `wiki_contents` DISABLE KEYS */;
/*!40000 ALTER TABLE `wiki_contents` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `wiki_pages`
--

DROP TABLE IF EXISTS `wiki_pages`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `wiki_pages` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `wiki_id` int(11) NOT NULL,
  `title` varchar(255) NOT NULL,
  `created_on` datetime NOT NULL,
  `protected` tinyint(1) NOT NULL DEFAULT '0',
  `parent_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `wiki_pages_wiki_id_title` (`wiki_id`,`title`),
  KEY `index_wiki_pages_on_wiki_id` (`wiki_id`),
  KEY `index_wiki_pages_on_parent_id` (`parent_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `wiki_pages`
--

LOCK TABLES `wiki_pages` WRITE;
/*!40000 ALTER TABLE `wiki_pages` DISABLE KEYS */;
/*!40000 ALTER TABLE `wiki_pages` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `wiki_redirects`
--

DROP TABLE IF EXISTS `wiki_redirects`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `wiki_redirects` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `wiki_id` int(11) NOT NULL,
  `title` varchar(255) DEFAULT NULL,
  `redirects_to` varchar(255) DEFAULT NULL,
  `created_on` datetime NOT NULL,
  `redirects_to_wiki_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `wiki_redirects_wiki_id_title` (`wiki_id`,`title`),
  KEY `index_wiki_redirects_on_wiki_id` (`wiki_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `wiki_redirects`
--

LOCK TABLES `wiki_redirects` WRITE;
/*!40000 ALTER TABLE `wiki_redirects` DISABLE KEYS */;
/*!40000 ALTER TABLE `wiki_redirects` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `wikis`
--

DROP TABLE IF EXISTS `wikis`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `wikis` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `project_id` int(11) NOT NULL,
  `start_page` varchar(255) NOT NULL,
  `status` int(11) NOT NULL DEFAULT '1',
  PRIMARY KEY (`id`),
  KEY `wikis_project_id` (`project_id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `wikis`
--

LOCK TABLES `wikis` WRITE;
/*!40000 ALTER TABLE `wikis` DISABLE KEYS */;
/*!40000 ALTER TABLE `wikis` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `workflows`
--

DROP TABLE IF EXISTS `workflows`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `workflows` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `tracker_id` int(11) NOT NULL DEFAULT '0',
  `old_status_id` int(11) NOT NULL DEFAULT '0',
  `new_status_id` int(11) NOT NULL DEFAULT '0',
  `role_id` int(11) NOT NULL DEFAULT '0',
  `assignee` tinyint(1) NOT NULL DEFAULT '0',
  `author` tinyint(1) NOT NULL DEFAULT '0',
  `type` varchar(30) DEFAULT NULL,
  `field_name` varchar(30) DEFAULT NULL,
  `rule` varchar(30) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `wkfs_role_tracker_old_status` (`role_id`,`tracker_id`,`old_status_id`),
  KEY `index_workflows_on_old_status_id` (`old_status_id`),
  KEY `index_workflows_on_role_id` (`role_id`),
  KEY `index_workflows_on_new_status_id` (`new_status_id`),
  KEY `index_workflows_on_tracker_id` (`tracker_id`)
) ENGINE=InnoDB AUTO_INCREMENT=767 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `workflows`
--

LOCK TABLES `workflows` WRITE;
/*!40000 ALTER TABLE `workflows` DISABLE KEYS */;
INSERT INTO `workflows` VALUES (132,1,2,0,3,0,0,'WorkflowPermission','14','readonly'),(134,1,2,0,3,0,0,'WorkflowPermission','16','readonly'),(151,1,3,0,3,0,0,'WorkflowPermission','14','readonly'),(153,1,3,0,3,0,0,'WorkflowPermission','16','readonly'),(170,1,4,0,3,0,0,'WorkflowPermission','14','readonly'),(172,1,4,0,3,0,0,'WorkflowPermission','16','readonly'),(189,1,5,0,3,0,0,'WorkflowPermission','14','readonly'),(191,1,5,0,3,0,0,'WorkflowPermission','16','readonly'),(208,1,6,0,3,0,0,'WorkflowPermission','14','readonly'),(210,1,6,0,3,0,0,'WorkflowPermission','16','readonly'),(220,1,2,3,3,0,0,'WorkflowTransition',NULL,NULL),(221,1,2,3,4,0,0,'WorkflowTransition',NULL,NULL),(222,1,2,3,5,0,0,'WorkflowTransition',NULL,NULL),(226,1,3,4,3,0,0,'WorkflowTransition',NULL,NULL),(227,1,3,4,4,0,0,'WorkflowTransition',NULL,NULL),(228,1,3,4,5,0,0,'WorkflowTransition',NULL,NULL),(229,1,4,5,3,0,0,'WorkflowTransition',NULL,NULL),(230,1,4,5,4,0,0,'WorkflowTransition',NULL,NULL),(231,1,4,5,5,0,0,'WorkflowTransition',NULL,NULL),(232,1,4,6,3,0,0,'WorkflowTransition',NULL,NULL),(233,1,4,6,4,0,0,'WorkflowTransition',NULL,NULL),(234,1,4,6,5,0,0,'WorkflowTransition',NULL,NULL),(239,1,2,0,4,0,0,'WorkflowPermission','priority_id','readonly'),(240,1,3,0,4,0,0,'WorkflowPermission','priority_id','readonly'),(241,1,4,0,4,0,0,'WorkflowPermission','priority_id','readonly'),(242,1,5,0,4,0,0,'WorkflowPermission','priority_id','readonly'),(243,1,6,0,4,0,0,'WorkflowPermission','priority_id','readonly'),(244,1,0,2,5,0,0,'WorkflowTransition',NULL,NULL),(245,1,0,2,4,0,0,'WorkflowTransition',NULL,NULL),(246,1,0,6,5,0,0,'WorkflowTransition',NULL,NULL),(352,1,2,0,3,0,0,'WorkflowPermission','project_id','readonly'),(353,1,2,0,3,0,0,'WorkflowPermission','tracker_id','readonly'),(354,1,2,0,3,0,0,'WorkflowPermission','subject','readonly'),(355,1,2,0,3,0,0,'WorkflowPermission','priority_id','readonly'),(356,1,2,0,3,0,0,'WorkflowPermission','is_private','readonly'),(357,1,2,0,3,0,0,'WorkflowPermission','description','readonly'),(358,1,2,0,3,0,0,'WorkflowPermission','1','readonly'),(359,1,2,0,3,0,0,'WorkflowPermission','2','readonly'),(360,1,2,0,3,0,0,'WorkflowPermission','10','readonly'),(361,1,2,0,3,0,0,'WorkflowPermission','20','readonly'),(362,1,2,0,3,0,0,'WorkflowPermission','8','readonly'),(363,1,2,0,3,0,0,'WorkflowPermission','15','readonly'),(364,1,2,0,3,0,0,'WorkflowPermission','11','readonly'),(365,1,2,0,3,0,0,'WorkflowPermission','12','readonly'),(366,1,2,0,3,0,0,'WorkflowPermission','19','readonly'),(367,1,2,0,3,0,0,'WorkflowPermission','7','readonly'),(368,1,2,0,3,0,0,'WorkflowPermission','3','readonly'),(369,1,2,0,3,0,0,'WorkflowPermission','5','readonly'),(370,1,2,0,3,0,0,'WorkflowPermission','6','readonly'),(371,1,2,0,3,0,0,'WorkflowPermission','22','readonly'),(372,1,3,0,3,0,0,'WorkflowPermission','project_id','readonly'),(373,1,3,0,3,0,0,'WorkflowPermission','tracker_id','readonly'),(374,1,3,0,3,0,0,'WorkflowPermission','subject','readonly'),(375,1,3,0,3,0,0,'WorkflowPermission','priority_id','readonly'),(376,1,3,0,3,0,0,'WorkflowPermission','is_private','readonly'),(377,1,3,0,3,0,0,'WorkflowPermission','description','readonly'),(378,1,3,0,3,0,0,'WorkflowPermission','1','readonly'),(379,1,3,0,3,0,0,'WorkflowPermission','2','readonly'),(380,1,3,0,3,0,0,'WorkflowPermission','10','readonly'),(381,1,3,0,3,0,0,'WorkflowPermission','20','readonly'),(382,1,3,0,3,0,0,'WorkflowPermission','8','readonly'),(383,1,3,0,3,0,0,'WorkflowPermission','15','readonly'),(384,1,3,0,3,0,0,'WorkflowPermission','11','readonly'),(385,1,3,0,3,0,0,'WorkflowPermission','12','readonly'),(386,1,3,0,3,0,0,'WorkflowPermission','19','readonly'),(387,1,3,0,3,0,0,'WorkflowPermission','7','readonly'),(388,1,3,0,3,0,0,'WorkflowPermission','3','readonly'),(389,1,3,0,3,0,0,'WorkflowPermission','5','readonly'),(390,1,3,0,3,0,0,'WorkflowPermission','6','readonly'),(391,1,3,0,3,0,0,'WorkflowPermission','22','readonly'),(392,1,4,0,3,0,0,'WorkflowPermission','project_id','readonly'),(393,1,4,0,3,0,0,'WorkflowPermission','tracker_id','readonly'),(394,1,4,0,3,0,0,'WorkflowPermission','subject','readonly'),(395,1,4,0,3,0,0,'WorkflowPermission','priority_id','readonly'),(396,1,4,0,3,0,0,'WorkflowPermission','is_private','readonly'),(397,1,4,0,3,0,0,'WorkflowPermission','description','readonly'),(398,1,4,0,3,0,0,'WorkflowPermission','1','readonly'),(399,1,4,0,3,0,0,'WorkflowPermission','2','readonly'),(400,1,4,0,3,0,0,'WorkflowPermission','10','readonly'),(401,1,4,0,3,0,0,'WorkflowPermission','20','readonly'),(402,1,4,0,3,0,0,'WorkflowPermission','8','readonly'),(403,1,4,0,3,0,0,'WorkflowPermission','15','readonly'),(404,1,4,0,3,0,0,'WorkflowPermission','11','readonly'),(405,1,4,0,3,0,0,'WorkflowPermission','12','readonly'),(406,1,4,0,3,0,0,'WorkflowPermission','19','readonly'),(407,1,4,0,3,0,0,'WorkflowPermission','7','readonly'),(408,1,4,0,3,0,0,'WorkflowPermission','3','readonly'),(409,1,4,0,3,0,0,'WorkflowPermission','5','readonly'),(410,1,4,0,3,0,0,'WorkflowPermission','6','readonly'),(411,1,4,0,3,0,0,'WorkflowPermission','22','readonly'),(412,1,5,0,3,0,0,'WorkflowPermission','project_id','readonly'),(413,1,5,0,3,0,0,'WorkflowPermission','tracker_id','readonly'),(414,1,5,0,3,0,0,'WorkflowPermission','subject','readonly'),(415,1,5,0,3,0,0,'WorkflowPermission','priority_id','readonly'),(416,1,5,0,3,0,0,'WorkflowPermission','is_private','readonly'),(417,1,5,0,3,0,0,'WorkflowPermission','description','readonly'),(418,1,5,0,3,0,0,'WorkflowPermission','1','readonly'),(419,1,5,0,3,0,0,'WorkflowPermission','2','readonly'),(420,1,5,0,3,0,0,'WorkflowPermission','10','readonly'),(421,1,5,0,3,0,0,'WorkflowPermission','20','readonly'),(422,1,5,0,3,0,0,'WorkflowPermission','8','readonly'),(423,1,5,0,3,0,0,'WorkflowPermission','15','readonly'),(424,1,5,0,3,0,0,'WorkflowPermission','11','readonly'),(425,1,5,0,3,0,0,'WorkflowPermission','12','readonly'),(426,1,5,0,3,0,0,'WorkflowPermission','19','readonly'),(427,1,5,0,3,0,0,'WorkflowPermission','7','readonly'),(428,1,5,0,3,0,0,'WorkflowPermission','3','readonly'),(429,1,5,0,3,0,0,'WorkflowPermission','5','readonly'),(430,1,5,0,3,0,0,'WorkflowPermission','6','readonly'),(431,1,5,0,3,0,0,'WorkflowPermission','22','readonly'),(432,1,6,0,3,0,0,'WorkflowPermission','project_id','readonly'),(433,1,6,0,3,0,0,'WorkflowPermission','tracker_id','readonly'),(434,1,6,0,3,0,0,'WorkflowPermission','subject','readonly'),(435,1,6,0,3,0,0,'WorkflowPermission','priority_id','readonly'),(436,1,6,0,3,0,0,'WorkflowPermission','is_private','readonly'),(437,1,6,0,3,0,0,'WorkflowPermission','description','readonly'),(438,1,6,0,3,0,0,'WorkflowPermission','1','readonly'),(439,1,6,0,3,0,0,'WorkflowPermission','2','readonly'),(440,1,6,0,3,0,0,'WorkflowPermission','10','readonly'),(441,1,6,0,3,0,0,'WorkflowPermission','20','readonly'),(442,1,6,0,3,0,0,'WorkflowPermission','8','readonly'),(443,1,6,0,3,0,0,'WorkflowPermission','15','readonly'),(444,1,6,0,3,0,0,'WorkflowPermission','11','readonly'),(445,1,6,0,3,0,0,'WorkflowPermission','12','readonly'),(446,1,6,0,3,0,0,'WorkflowPermission','19','readonly'),(447,1,6,0,3,0,0,'WorkflowPermission','7','readonly'),(448,1,6,0,3,0,0,'WorkflowPermission','3','readonly'),(449,1,6,0,3,0,0,'WorkflowPermission','5','readonly'),(450,1,6,0,3,0,0,'WorkflowPermission','6','readonly'),(451,1,6,0,3,0,0,'WorkflowPermission','22','readonly'),(642,1,2,3,2,0,0,'WorkflowTransition',NULL,NULL),(644,1,3,4,2,0,0,'WorkflowTransition',NULL,NULL),(645,1,4,5,2,0,0,'WorkflowTransition',NULL,NULL),(646,1,4,6,2,0,0,'WorkflowTransition',NULL,NULL),(648,1,4,3,2,0,0,'WorkflowTransition',NULL,NULL),(649,1,4,3,3,0,0,'WorkflowTransition',NULL,NULL),(650,1,4,3,4,0,0,'WorkflowTransition',NULL,NULL),(651,1,4,3,5,0,0,'WorkflowTransition',NULL,NULL),(652,1,2,0,2,0,0,'WorkflowPermission','project_id','readonly'),(653,1,2,0,2,0,0,'WorkflowPermission','tracker_id','readonly'),(654,1,2,0,2,0,0,'WorkflowPermission','subject','readonly'),(655,1,2,0,2,0,0,'WorkflowPermission','priority_id','readonly'),(656,1,2,0,2,0,0,'WorkflowPermission','is_private','readonly'),(657,1,2,0,2,0,0,'WorkflowPermission','description','readonly'),(658,1,2,0,2,0,0,'WorkflowPermission','1','readonly'),(659,1,2,0,2,0,0,'WorkflowPermission','2','readonly'),(660,1,2,0,2,0,0,'WorkflowPermission','10','readonly'),(661,1,2,0,2,0,0,'WorkflowPermission','20','readonly'),(662,1,2,0,2,0,0,'WorkflowPermission','8','readonly'),(663,1,2,0,2,0,0,'WorkflowPermission','15','readonly'),(664,1,2,0,2,0,0,'WorkflowPermission','11','readonly'),(665,1,2,0,2,0,0,'WorkflowPermission','12','readonly'),(666,1,2,0,2,0,0,'WorkflowPermission','27','readonly'),(667,1,2,0,2,0,0,'WorkflowPermission','28','readonly'),(668,1,2,0,2,0,0,'WorkflowPermission','19','readonly'),(669,1,2,0,2,0,0,'WorkflowPermission','17','readonly'),(670,1,2,0,2,0,0,'WorkflowPermission','7','readonly'),(671,1,2,0,2,0,0,'WorkflowPermission','3','readonly'),(672,1,2,0,2,0,0,'WorkflowPermission','5','readonly'),(673,1,2,0,2,0,0,'WorkflowPermission','6','readonly'),(674,1,2,0,2,0,0,'WorkflowPermission','22','readonly'),(675,1,3,0,2,0,0,'WorkflowPermission','project_id','readonly'),(676,1,3,0,2,0,0,'WorkflowPermission','tracker_id','readonly'),(677,1,3,0,2,0,0,'WorkflowPermission','subject','readonly'),(678,1,3,0,2,0,0,'WorkflowPermission','priority_id','readonly'),(679,1,3,0,2,0,0,'WorkflowPermission','is_private','readonly'),(680,1,3,0,2,0,0,'WorkflowPermission','description','readonly'),(681,1,3,0,2,0,0,'WorkflowPermission','1','readonly'),(682,1,3,0,2,0,0,'WorkflowPermission','2','readonly'),(683,1,3,0,2,0,0,'WorkflowPermission','10','readonly'),(684,1,3,0,2,0,0,'WorkflowPermission','20','readonly'),(685,1,3,0,2,0,0,'WorkflowPermission','8','readonly'),(686,1,3,0,2,0,0,'WorkflowPermission','15','readonly'),(687,1,3,0,2,0,0,'WorkflowPermission','11','readonly'),(688,1,3,0,2,0,0,'WorkflowPermission','12','readonly'),(689,1,3,0,2,0,0,'WorkflowPermission','27','readonly'),(690,1,3,0,2,0,0,'WorkflowPermission','28','readonly'),(691,1,3,0,2,0,0,'WorkflowPermission','19','readonly'),(692,1,3,0,2,0,0,'WorkflowPermission','17','readonly'),(693,1,3,0,2,0,0,'WorkflowPermission','7','readonly'),(694,1,3,0,2,0,0,'WorkflowPermission','3','readonly'),(695,1,3,0,2,0,0,'WorkflowPermission','5','readonly'),(696,1,3,0,2,0,0,'WorkflowPermission','6','readonly'),(697,1,3,0,2,0,0,'WorkflowPermission','22','readonly'),(698,1,4,0,2,0,0,'WorkflowPermission','project_id','readonly'),(699,1,4,0,2,0,0,'WorkflowPermission','tracker_id','readonly'),(700,1,4,0,2,0,0,'WorkflowPermission','subject','readonly'),(701,1,4,0,2,0,0,'WorkflowPermission','priority_id','readonly'),(702,1,4,0,2,0,0,'WorkflowPermission','is_private','readonly'),(703,1,4,0,2,0,0,'WorkflowPermission','description','readonly'),(704,1,4,0,2,0,0,'WorkflowPermission','1','readonly'),(705,1,4,0,2,0,0,'WorkflowPermission','2','readonly'),(706,1,4,0,2,0,0,'WorkflowPermission','10','readonly'),(707,1,4,0,2,0,0,'WorkflowPermission','20','readonly'),(708,1,4,0,2,0,0,'WorkflowPermission','8','readonly'),(709,1,4,0,2,0,0,'WorkflowPermission','15','readonly'),(710,1,4,0,2,0,0,'WorkflowPermission','11','readonly'),(711,1,4,0,2,0,0,'WorkflowPermission','12','readonly'),(712,1,4,0,2,0,0,'WorkflowPermission','27','readonly'),(713,1,4,0,2,0,0,'WorkflowPermission','28','readonly'),(714,1,4,0,2,0,0,'WorkflowPermission','19','readonly'),(715,1,4,0,2,0,0,'WorkflowPermission','17','readonly'),(716,1,4,0,2,0,0,'WorkflowPermission','7','readonly'),(717,1,4,0,2,0,0,'WorkflowPermission','3','readonly'),(718,1,4,0,2,0,0,'WorkflowPermission','5','readonly'),(719,1,4,0,2,0,0,'WorkflowPermission','6','readonly'),(720,1,4,0,2,0,0,'WorkflowPermission','22','readonly'),(721,1,5,0,2,0,0,'WorkflowPermission','project_id','readonly'),(722,1,5,0,2,0,0,'WorkflowPermission','tracker_id','readonly'),(723,1,5,0,2,0,0,'WorkflowPermission','subject','readonly'),(724,1,5,0,2,0,0,'WorkflowPermission','priority_id','readonly'),(725,1,5,0,2,0,0,'WorkflowPermission','is_private','readonly'),(726,1,5,0,2,0,0,'WorkflowPermission','description','readonly'),(727,1,5,0,2,0,0,'WorkflowPermission','1','readonly'),(728,1,5,0,2,0,0,'WorkflowPermission','2','readonly'),(729,1,5,0,2,0,0,'WorkflowPermission','10','readonly'),(730,1,5,0,2,0,0,'WorkflowPermission','20','readonly'),(731,1,5,0,2,0,0,'WorkflowPermission','8','readonly'),(732,1,5,0,2,0,0,'WorkflowPermission','15','readonly'),(733,1,5,0,2,0,0,'WorkflowPermission','11','readonly'),(734,1,5,0,2,0,0,'WorkflowPermission','12','readonly'),(735,1,5,0,2,0,0,'WorkflowPermission','27','readonly'),(736,1,5,0,2,0,0,'WorkflowPermission','28','readonly'),(737,1,5,0,2,0,0,'WorkflowPermission','19','readonly'),(738,1,5,0,2,0,0,'WorkflowPermission','17','readonly'),(739,1,5,0,2,0,0,'WorkflowPermission','7','readonly'),(740,1,5,0,2,0,0,'WorkflowPermission','3','readonly'),(741,1,5,0,2,0,0,'WorkflowPermission','5','readonly'),(742,1,5,0,2,0,0,'WorkflowPermission','6','readonly'),(743,1,5,0,2,0,0,'WorkflowPermission','22','readonly'),(744,1,6,0,2,0,0,'WorkflowPermission','project_id','readonly'),(745,1,6,0,2,0,0,'WorkflowPermission','tracker_id','readonly'),(746,1,6,0,2,0,0,'WorkflowPermission','subject','readonly'),(747,1,6,0,2,0,0,'WorkflowPermission','priority_id','readonly'),(748,1,6,0,2,0,0,'WorkflowPermission','is_private','readonly'),(749,1,6,0,2,0,0,'WorkflowPermission','description','readonly'),(750,1,6,0,2,0,0,'WorkflowPermission','1','readonly'),(751,1,6,0,2,0,0,'WorkflowPermission','2','readonly'),(752,1,6,0,2,0,0,'WorkflowPermission','10','readonly'),(753,1,6,0,2,0,0,'WorkflowPermission','20','readonly'),(754,1,6,0,2,0,0,'WorkflowPermission','8','readonly'),(755,1,6,0,2,0,0,'WorkflowPermission','15','readonly'),(756,1,6,0,2,0,0,'WorkflowPermission','11','readonly'),(757,1,6,0,2,0,0,'WorkflowPermission','12','readonly'),(758,1,6,0,2,0,0,'WorkflowPermission','27','readonly'),(759,1,6,0,2,0,0,'WorkflowPermission','28','readonly'),(760,1,6,0,2,0,0,'WorkflowPermission','19','readonly'),(761,1,6,0,2,0,0,'WorkflowPermission','17','readonly'),(762,1,6,0,2,0,0,'WorkflowPermission','7','readonly'),(763,1,6,0,2,0,0,'WorkflowPermission','3','readonly'),(764,1,6,0,2,0,0,'WorkflowPermission','5','readonly'),(765,1,6,0,2,0,0,'WorkflowPermission','6','readonly'),(766,1,6,0,2,0,0,'WorkflowPermission','22','readonly');
/*!40000 ALTER TABLE `workflows` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2020-12-08  3:05:36
