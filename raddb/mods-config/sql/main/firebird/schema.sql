###########################################################################
# $Id$                         #
#                                                                         #
#  schema.sql                       rlm_sql - FreeRADIUS SQL Module       #
#                                                                         #
#     Database schema for Firebird rlm_sql module                         #
#                                                                         #
###########################################################################
#
# Table structure for table 'radacct'
#

CREATE TABLE radacct (
  radacctid BIGINT GENERATED BY DEFAULT AS IDENTITY,
  acctsessionid VARCHAR(64) DEFAULT '' NOT NULL,
  acctuniqueid VARCHAR(32) DEFAULT '' NOT NULL,
  username VARCHAR(64) DEFAULT '' NOT NULL,
  groupname VARCHAR(64) DEFAULT '' NOT NULL,
  realm VARCHAR(64) DEFAULT '',
  nasipaddress VARCHAR(15) DEFAULT '' NOT NULL,
  nasportid VARCHAR(32),
  nasporttype VARCHAR(32),
  acctstarttime TIMESTAMP,
  acctupdatetime TIMESTAMP,
  acctstoptime TIMESTAMP,
  acctinterval INTEGER,
  acctsessiontime INTEGER,
  acctauthentic VARCHAR(32),
  connectinfo_start VARCHAR(50),
  connectinfo_stop VARCHAR(50),
  acctinputoctets BIGINT,
  acctoutputoctets BIGINT,
  calledstationid VARCHAR(50) DEFAULT '' NOT NULL,
  callingstationid VARCHAR(50) DEFAULT '' NOT NULL,
  acctterminatecause VARCHAR(32) DEFAULT '' NOT NULL,
  servicetype VARCHAR(32),
  framedprotocol VARCHAR(32),
  framedipaddress VARCHAR(15) DEFAULT '' NOT NULL,
  framedipv6address VARCHAR(45) DEFAULT '' NOT NULL,
  framedipv6prefix VARCHAR(45) DEFAULT '' NOT NULL,
  framedinterfaceid VARCHAR(44) DEFAULT '' NOT NULL,
  delegatedipv6prefix VARCHAR(45) DEFAULT '' NOT NULL,
  class VARCHAR(64)
);

CREATE UNIQUE INDEX radacct_unique ON radacct (acctuniqueid);
CREATE INDEX radacct_session ON radacct (acctsessionid);
CREATE INDEX radacct_user ON radacct (username);
CREATE INDEX radacct_framedip ON radacct (framedipaddress);
CREATE INDEX radacct_framedipv6addr ON radacct (framedipv6address);
CREATE INDEX radacct_framedipv6pref ON radacct (framedipv6prefix);
CREATE INDEX radacct_acctstarttime ON radacct (acctstarttime);
CREATE INDEX radacct_acctstoptime ON radacct (acctstoptime, nasipaddress, acctstarttime);
CREATE INDEX radacct_nasipaddress ON radacct (nasipaddress);

COMMIT;

#
# Table structure for table 'radcheck'
# Notes:
#  - `value` is a keyword, so this schema uses attrvalue
#  - `op` is defined as a VARCHAR since Firebird returns trailing spaces on fixed length strings
#

CREATE TABLE radcheck (
  id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  username VARCHAR(64) DEFAULT '' NOT NULL,
  attribute VARCHAR(64) DEFAULT '' NOT NULL,
  op VARCHAR(2) DEFAULT '==' NOT NULL,
  attrvalue VARCHAR(253) DEFAULT '' NOT NULL
);

CREATE INDEX radcheck_user ON radcheck (username);

COMMIT;

#
# Table structure for table 'radgroupcheck'
#

CREATE TABLE radgroupcheck (
  id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  groupname VARCHAR(64) DEFAULT '' NOT NULL,
  attribute VARCHAR(64) DEFAULT '' NOT NULL,
  op VARCHAR(2) DEFAULT '==' NOT NULL,
  attrvalue VARCHAR(253) DEFAULT '' NOT NULL
);

CREATE INDEX radgroupcheck_group ON radgroupcheck (groupname);

COMMIT;

#
# Table structure for table 'radgroupreply'
#

CREATE TABLE radgroupreply (
  id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  groupname VARCHAR(64) DEFAULT '' NOT NULL,
  attribute VARCHAR(64) DEFAULT '' NOT NULL,
  op VARCHAR(2) DEFAULT '=' NOT NULL,
  attrvalue VARCHAR(253) DEFAULT ''
);

CREATE INDEX radgroupreply_group ON radgroupreply (groupname);

COMMIT;

#
# Table structure for table 'radreply'
#

CREATE TABLE radreply (
  id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  username VARCHAR(64) DEFAULT '' NOT NULL,
  attribute VARCHAR(64) DEFAULT '' NOT NULL,
  op VARCHAR(2) DEFAULT '"' NOT NULL,
  attrvalue VARCHAR(253) DEFAULT '' NOT NULL
);

CREATE INDEX radreply_user ON radreply (username);

COMMIT;

#
# Table structure for table 'radusergroup'
#

CREATE TABLE radusergroup (
  id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  username VARCHAR(64) DEFAULT '' NOT NULL,
  groupname VARCHAR(64) DEFAULT '' NOT NULL,
  priority INTEGER DEFAULT 1 NOT NULL
);

CREATE INDEX radusergroup_user ON radusergroup (username);

COMMIT;

#
# Table structure for table 'radpostauth'
#
CREATE TABLE radpostauth (
  id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  username VARCHAR(64) DEFAULT '' NOT NULL,
  pass VARCHAR(64) DEFAULT '' NOT NULL,
  reply VARCHAR(32) DEFAULT '' NOT NULL,
  authdate TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
  class VARCHAR(64) DEFAULT '' NOT NULL
);

COMMIT;

#
# Table structure for table 'nas'
#
CREATE TABLE nas (
  id INTEGER GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  nasname VARCHAR(128) NOT NULL,
  shortname VARCHAR(32),
  type VARCHAR(30) DEFAULT 'other',
  ports INTEGER,
  secret VARCHAR(60) DEFAULT 'secret' NOT NULL,
  server VARCHAR(64),
  community VARCHAR(50),
  description VARCHAR(200) DEFAULT 'RADIUS Client'
);

CREATE INDEX nas_name ON nas (nasname);

COMMIT;

#
# Table structure for table 'nasreload'
#
CREATE TABLE nasreload (
  nasipaddress VARCHAR(15) NOT NULL PRIMARY KEY,
  reloadtime TIMESTAMP NOT NULL
);

COMMIT;