package monitor

import (
	"embed"
	"io/fs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrations returns the embedded monitor-database migration files, rooted
// so filenames appear without the "migrations/" prefix.
func Migrations() fs.FS {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		panic(err) // embed path is a compile-time constant; this can't fail
	}
	return sub
}
