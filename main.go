// Copyright 2017 Artyom Pervukhin. All rights reserved.  Use of this source
// code is governed by a MIT license that can be found in the LICENSE.txt file.

// Command shadowdb creates a new MySQL database that contains VIEWs pointing to
// original database tables with content of sensitive columns masked.
//
// Operation mode
//
// The use case for shadowdb is to have a read-only MySQL database similar to
// the original one but with some sensitive text information replaced by
// placeholders. Naturally one can use MySQL permissions system to only grant
// SELECT privilege to subset of table columns, but this approach breaks
// programs which expect to be able to read values of sensitive columns as well.
//
// Such scenario can be handled by creating a separate database with SQL VIEWs
// referencing original database tables but returning placeholder values for
// columns with sensitive data.
//
// Consider the following table:
//
// 	create table original_db.users (
//		id integer auto_increment primary key,
//		name varchar(100),
//		email varchar(100)
// 	)
//
// Here's an example of query against such table:
//
//	> select * from original_db.users;
//	+----+----------+------------------+
//	| id | name     | email            |
//	+----+----------+------------------+
//	|  1 | John Doe | john@example.com |
//	+----+----------+------------------+
//
// The view limiting visibility of the "name" column for such table can be created
// like this:
//
//	create view masked_db.users (id, name, email) as
//		select id, '*****', email from original_db.users
//
// Now query against masked_db.users view returns the same number of columns as
// original_db.users, but has asterisks in place of the "name" column values:
//
//	> select * from masked_db.users;
//	+----+-------+------------------+
//	| id | name  | email            |
//	+----+-------+------------------+
//	|  1 | ***** | john@example.com |
//	+----+-------+------------------+
//
// Command shadowdb automates such process by discovering fields of each table
// in the original database and creating (or updating) corresponding views for
// them, masking provided sensitive fields. Additionally this command
// creates/updates privileges for the given MySQL user so that such user can
// only select non-masked fields from the original database and all fields of
// the created views.
//
// Notes
//
// If original database schema changes, shadowdb command should be run again
// — it will update views to reflect original database tables. Note that it does
// not remove views for dropped tables, you have to manually do this.
//
// shadowdb automatically creates destination (masked) database as necessary, as
// well as the user to grant select privileges to. It does not configure
// authorization for such user.
//
// List of sensitive fields is expected to be in CSV format of
// table_name,column_name pairs (case insensitive) without header, see the -mask flag. It is
// implied that masked columns are of some text type (varchar, etc.), if they're
// not, clients working with created views may be surprised by seeing text
// placeholder value instead of non-text type of the original table.
//
// MySQL credentials (user and password) are read from the "client" section of
// the .my.cnf file which is expected to have the following format:
//
// 	[client]
// 	user = username
// 	password = password
//
// The user is expected to have SUPER privileges (or their subset sufficient to
// create databases, views and grant privileges).
//
// If -tls flag is used, program connects to the server over TLS and expects
// server certificate to be signed with certificate authority from the system CA
// pool. On UNIX systems the environment variables SSL_CERT_FILE and
// SSL_CERT_DIR can be used to override the system default locations for the SSL
// certificate file and SSL certificate files directory, respectively.
package main

import (
	"bufio"
	"bytes"
	"database/sql"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/artyom/autoflags"
	"github.com/go-sql-driver/mysql"
)

func main() {
	args := runArgs{
		Creds: filepath.Join(os.Getenv("HOME"), ".my.cnf"),
	}
	autoflags.Parse(&args)
	if err := run(args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type runArgs struct {
	Creds    string `flag:"mycnf,path to .my.cnf file to read user/password from"`
	Database string `flag:"db,source database name"`
	Shadow   string `flag:"shadow,destination database name"`
	User     string `flag:"user,user to grant restricted select privileges"`
	Mask     string `flag:"mask,CSV file with table,column names to mask"`
	Addr     string `flag:"addr,MySQL server address, host:port or /path/to/socket"`
	TLS      bool   `flag:"tls,establish TLS connection (TCP mode only)"`
}

func (args *runArgs) check() error {
	if args.Addr == "" {
		return fmt.Errorf("server address cannot be empty")
	}
	if args.Mask == "" {
		return fmt.Errorf("mask cannot be empty")
	}
	if !validName(args.Database) {
		return fmt.Errorf("invalid source database name")
	}
	if !validName(args.Shadow) {
		return fmt.Errorf("invalid shadow database name")
	}
	if args.Shadow == args.Database {
		return fmt.Errorf("db and shadow cannot be the same")
	}
	if !validName(args.User) {
		return fmt.Errorf("invalid restricted user name")
	}
	return nil
}

func run(args runArgs) error {
	if err := args.check(); err != nil {
		return err
	}
	mask, err := privateFields(args.Mask)
	if err != nil {
		return err
	}
	if len(mask) == 0 {
		return fmt.Errorf("%q has no records", args.Mask)
	}
	cfg := mysql.NewConfig()
	cfg.Addr, cfg.Net = args.Addr, "tcp"
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout, cfg.WriteTimeout = 10*time.Second, 10*time.Second
	if args.TLS {
		cfg.TLSConfig = "yes"
	}
	if strings.ContainsRune(args.Addr, os.PathSeparator) {
		cfg.Net, cfg.TLSConfig = "unix", ""
	}
	if cfg.User, cfg.Passwd, err = parseMyCNF(args.Creds); err != nil {
		return err
	}
	if cfg.User == args.User {
		return fmt.Errorf("user name from .my.cnf cannot be the same as provided by -user flag")
	}
	connector, err := mysql.NewConnector(cfg)
	if err != nil {
		return err
	}
	db := sql.OpenDB(connector)
	defer db.Close()
	tables, err := databaseTables(db, args.Database)
	if err != nil {
		return fmt.Errorf("database tables retrieve: %w", err)
	}
	if len(tables) == 0 {
		return fmt.Errorf("database has no tables")
	}
	if _, err := db.Exec(`create database if not exists ` + args.Shadow); err != nil {
		return fmt.Errorf("destination database create: %w", err)
	}
	if err := createUser(db, args.User); err != nil {
		return fmt.Errorf("create user: %w", err)
	}
	for _, table := range tables {
		if err := createView(db, args.Database, args.Shadow, table, args.User, mask); err != nil {
			return fmt.Errorf("table %q: %w", table, err)
		}
	}
	return nil
}

// readDSN parses .my.cnf and returns found user and password
func parseMyCNF(name string) (user, password string, err error) {
	f, err := os.Open(name)
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	var clientSection bool
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 || b[0] == '#' {
			continue
		}
		if b[0] == '[' {
			clientSection = bytes.HasPrefix(b, []byte("[client]"))
			continue
		}
		if !clientSection {
			continue
		}
		bb := bytes.SplitN(b, []byte("="), 2)
		if len(bb) != 2 {
			continue
		}
		switch key := string(bytes.TrimSpace(bb[0])); key {
		case "user":
			user = string(bytes.TrimSpace(bb[1]))
		case "password":
			password = string(bytes.TrimSpace(bb[1]))
		}
	}
	if err := sc.Err(); err != nil {
		return "", "", err
	}
	if user == "" || password == "" {
		return "", "", fmt.Errorf("either user or password not found in %q", name)
	}
	return user, password, nil
}

// validName returns whether s is a valid name that can be used as unquoted
// MySQL identifier. It only returns true on non-empty strings of length up to
// 64 bytes containing characters in range [A-Za-z0-9_].
func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	// https://dev.mysql.com/doc/refman/5.6/en/identifiers.html
	for _, r := range s {
		switch {
		case '0' <= r && r <= '9':
		case 'A' <= r && r <= 'Z':
		case 'a' <= r && r <= 'z':
		case r == '_':
		default:
			return false
		}

	}
	return true
}

type fieldSpecSet map[fieldSpec]struct{}

type fieldSpec struct{ table, field string }

// privateFields reads file at path as 2-column csv stream of
// table_name,field_name pairs. Both table and field names are tested with
// validName check. Returned map is a set-like primitive for membership checks.
func privateFields(path string) (fieldSpecSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fields, err := readPrivateFields(f)
	if err != nil {
		return nil, err
	}
	out := make(fieldSpecSet, len(fields))
	for _, fs := range fields {
		out[fs] = struct{}{}
	}
	return out, nil
}

// readPrivateFields reads r as 2-column csv stream of table_name,field_name
// pairs. Both table and field names are tested with validName check.
func readPrivateFields(r io.Reader) ([]fieldSpec, error) {
	var out []fieldSpec
	rd := csv.NewReader(r)
	rd.FieldsPerRecord = 2
	rd.ReuseRecord = true
	for {
		rec, err := rd.Read()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
		for _, s := range rec {
			if !validName(s) {
				return nil, fmt.Errorf("csv read: %q is not a valid name", s)
			}
		}
		out = append(out, fieldSpec{strings.ToLower(rec[0]), strings.ToLower(rec[1])})
	}
}

// createView creates or updates view in the dstDB named the same as the table
// from srcDB, so that such view selects fields from the srcDB.table except for
// the ones that are found in mask set, which are replaced by the placeholder
// string value of multiple asterisks. createView updates user privileges on the
// srcDB.table to only select required columns (which are NOT present in mask)
// and grants select privilege on dstDB.table view.
func createView(db *sql.DB, srcDB, dstDB, table, user string, mask fieldSpecSet) error {
	cols, err := selectableColumns(db, srcDB, table)
	if err != nil {
		return err
	}
	if !validName(table) {
		return fmt.Errorf("%q is not a valid table name", table)
	}
	if !validName(user) {
		return fmt.Errorf("%q is not a valid user name", user)
	}
	if len(cols) == 0 {
		return fmt.Errorf("table %q has no selectable columns", table)
	}
	const placeholder = "'*****'" // MUST be safe to use directly in SQL expression
	vals := viewValues(table, placeholder, cols, mask)
	grantCols := make([]string, 0, len(cols))
	for i, name := range cols {
		if name == vals[i] {
			grantCols = append(grantCols, name)
		}
	}
	query := "REVOKE SELECT ON " + srcDB + ".* FROM '" + user + "'@'%'"
	if _, err := db.Exec(query); err != nil {
		if e, ok := err.(*mysql.MySQLError); ok && e.Number == 1141 {
			// ignore "Error 1141: There is no such grant defined for user"
		} else {
			return fmt.Errorf("privileges revoke: %w", err)
		}
	}

	query = "GRANT SELECT (" + strings.Join(grantCols, ",") + ") ON " + srcDB + "." + table +
		" TO '" + user + "'@'%'"
	if _, err := db.Exec(query); err != nil {
		return fmt.Errorf("source table privileges grant: %w", err)
	}

	query = "CREATE OR REPLACE SQL SECURITY INVOKER VIEW " +
		dstDB + "." + table + " (" + strings.Join(cols, ",") + ") AS SELECT " +
		strings.Join(vals, ",") + " FROM " + srcDB + "." + table
	if _, err := db.Exec(query); err != nil {
		return fmt.Errorf("create view: %w", err)
	}

	query = "GRANT SELECT ON " + dstDB + "." + table + " TO '" + user + "'@'%'"
	if _, err := db.Exec(query); err != nil {
		return fmt.Errorf("destination view privileges grant: %w", err)
	}
	return nil
}

// viewValues returns values that should be used in CREATE VIEW ...  list.
// Returned slice has column names from columns slice, with exception of the
// fields that can be found in the mask set; for those fields value is
// substituted with placeholder string, which should be an appropriately quoted
// string safe to be directly used in SQL expression.
func viewValues(table, placeholder string, columns []string, mask fieldSpecSet) []string {
	out := make([]string, len(columns))
	table = strings.ToLower(table)
	for i, field := range columns {
		switch _, ok := mask[fieldSpec{table: table, field: strings.ToLower(field)}]; {
		case ok:
			out[i] = placeholder
		default:
			out[i] = field
		}
	}
	return out
}

// selectableColumns returns list of readable columns for the given table as
// read from the information_schema.columns table.
func selectableColumns(db *sql.DB, database, table string) ([]string, error) {
	query := `select column_name from information_schema.columns
		where table_schema=? and table_name=? order by ordinal_position`
	rows, err := db.Query(query, database, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	var s string
	for rows.Next() {
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if !validName(s) {
			return nil, fmt.Errorf("%q is not a valid column name", s)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func databaseTables(db *sql.DB, database string) ([]string, error) {
	query := `select table_name from information_schema.tables where table_schema=?`
	rows, err := db.Query(query, database)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	var s string
	for rows.Next() {
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		if !validName(s) {
			return nil, fmt.Errorf("%q is not a valid table name", s)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func createUser(db *sql.DB, name string) error {
	var discard string
	query := `select user from mysql.user where user=?`
	switch err := db.QueryRow(query, name).Scan(&discard); err {
	case nil:
		return nil
	case sql.ErrNoRows:
	default:
		return err
	}
	_, err := db.Exec(`create user '` + name + "'")
	return err
}
