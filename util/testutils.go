package util

import (
	"database/sql"
	"os"

	_ "code.google.com/p/gosqlite/sqlite3"
	"github.com/endophage/go-tuf/data"
)

func SampleMeta() data.FileMeta {
	meta := data.FileMeta{
		Length: 1,
		Hashes: data.Hashes{
			"sha256": data.HexBytes{0x01, 0x02},
			"sha512": data.HexBytes{0x03, 0x04},
		},
	}
	return meta
}

func GetSqliteDB() *sql.DB {
	conn, err := sql.Open("sqlite3", "/tmp/file.db")
	if err != nil {
		panic("can't connect to db")
	}
	conn.Exec("CREATE TABLE keys (id int auto_increment, namespace varchar(255) not null, role varchar(255) not null, key text not null, primary key (id));")
	conn.Exec("CREATE TABLE filehashes(namespace varchar(255) not null, path varchar(255) not null, alg varchar(10) not null, hash varchar(128) not null, primary key (namespace, path, alg));")
	conn.Exec("CREATE TABLE filemeta(namespace varchar(255) not null, path varchar(255) not null, size int not null, custom text default null, primary key (namespace, path));")
	return conn
}

func FlushDB(db *sql.DB) {
	db.Exec("DELETE FROM `filemeta`")
	db.Exec("DELETE FROM `filehashes`")
	db.Exec("DELETE FROM `keys`")

	os.RemoveAll("/tmp/tuf")
}
