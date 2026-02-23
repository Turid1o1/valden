package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/google/uuid"
)

type deviceUpsertResult struct {
	DeviceID    string
	DeviceToken string
	PublicID    string
}

func normalizePublicID(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	builder := strings.Builder{}
	builder.Grow(len(input))
	for _, r := range input {
		if r >= '0' && r <= '9' {
			builder.WriteRune(r)
		}
	}
	return builder.String()
}

func formatPublicID(input string) string {
	trimmed := normalizePublicID(input)
	if len(trimmed) != 9 {
		return trimmed
	}
	return fmt.Sprintf("%s %s %s", trimmed[0:3], trimmed[3:6], trimmed[6:9])
}

func (a *App) generatePublicID(ctx context.Context, tx *sql.Tx) (string, error) {
	for i := 0; i < 20; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(900000000))
		if err != nil {
			return "", err
		}
		candidate := fmt.Sprintf("%09d", 100000000+n.Int64())
		var exists bool
		err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM devices WHERE public_id = $1)`, candidate).Scan(&exists)
		if err != nil {
			return "", err
		}
		if !exists {
			return candidate, nil
		}
	}
	return "", errors.New("failed to allocate public id")
}

func (a *App) upsertDevice(ctx context.Context, req registerDeviceRequest, user *authUser) (deviceUpsertResult, error) {
	result := deviceUpsertResult{}
	deviceKey := strings.TrimSpace(req.DeviceKey)
	if deviceKey == "" {
		return result, errors.New("device_key is required")
	}

	parts := strings.SplitN(deviceKey, ":", 2)
	secretPart := deviceKey
	if len(parts) == 2 {
		secretPart = parts[1]
	}
	deviceKeyHash := sha256Hex(deviceKey)
	secretHash := sha256Hex(secretPart)

	meta := req.DeviceMeta
	if meta == nil {
		meta = map[string]interface{}{}
	}
	if req.DeviceName != "" {
		meta["device_name"] = strings.TrimSpace(req.DeviceName)
	}
	metaBytes, err := json.Marshal(meta)
	if err != nil {
		return result, err
	}

	deviceToken, err := randomToken(32)
	if err != nil {
		return result, err
	}

	tx, err := a.db.BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return result, err
	}
	defer tx.Rollback()

	var existingDeviceID string
	var existingPublicID sql.NullString
	err = tx.QueryRowContext(
		ctx,
		`SELECT id, public_id FROM devices WHERE device_key_hash = $1 FOR UPDATE`,
		deviceKeyHash,
	).Scan(&existingDeviceID, &existingPublicID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return result, err
	}

	ownerID := sql.NullString{}
	if user != nil && strings.TrimSpace(user.ID) != "" {
		ownerID = sql.NullString{String: strings.TrimSpace(user.ID), Valid: true}
	}

	if errors.Is(err, sql.ErrNoRows) {
		publicID, genErr := a.generatePublicID(ctx, tx)
		if genErr != nil {
			return result, genErr
		}
		deviceID := uuid.NewString()
		_, err = tx.ExecContext(
			ctx,
			`INSERT INTO devices (id, device_key_hash, secret_hash, device_meta, token_hash, owner_user_id, public_id, device_name)
VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8)`,
			deviceID,
			deviceKeyHash,
			secretHash,
			string(metaBytes),
			sha256Hex(deviceToken),
			nullableStringArg(ownerID),
			publicID,
			nullIfEmpty(req.DeviceName),
		)
		if err != nil {
			return result, err
		}
		result.DeviceID = deviceID
		result.PublicID = publicID
	} else {
		_, err = tx.ExecContext(
			ctx,
			`UPDATE devices
SET secret_hash = $2,
    device_meta = $3::jsonb,
    token_hash = $4,
    owner_user_id = COALESCE($5, owner_user_id),
    device_name = COALESCE($6, device_name),
    updated_at = now()
WHERE id = $1`,
			existingDeviceID,
			secretHash,
			string(metaBytes),
			sha256Hex(deviceToken),
			nullableStringArg(ownerID),
			nullIfEmpty(req.DeviceName),
		)
		if err != nil {
			return result, err
		}
		result.DeviceID = existingDeviceID
		result.PublicID = existingPublicID.String
	}

	if err = tx.Commit(); err != nil {
		return result, err
	}

	result.DeviceToken = deviceToken
	result.PublicID = normalizePublicID(result.PublicID)
	return result, nil
}

func nullableStringArg(v sql.NullString) interface{} {
	if v.Valid {
		return v.String
	}
	return nil
}

func nullIfEmpty(value string) interface{} {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil
	}
	return trimmed
}

func (a *App) resolveDeviceIdentifier(ctx context.Context, input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", errors.New("empty device identifier")
	}

	if parsed, err := uuid.Parse(trimmed); err == nil {
		var existingID string
		err = a.db.QueryRowContext(ctx, `SELECT id FROM devices WHERE id = $1`, parsed.String()).Scan(&existingID)
		if err == nil {
			return existingID, nil
		}
	}

	publicID := normalizePublicID(trimmed)
	if len(publicID) == 9 {
		var deviceID string
		err := a.db.QueryRowContext(ctx, `SELECT id FROM devices WHERE public_id = $1`, publicID).Scan(&deviceID)
		if err == nil {
			return deviceID, nil
		}
	}

	return "", sql.ErrNoRows
}
