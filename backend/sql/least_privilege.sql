-- =====================================================================================
-- NMMVA CORP - Usuario de base de datos de MÍNIMO PRIVILEGIO (Defensa en Profundidad)
-- Ejecutar UNA vez como administrador (root) y luego configurar la app con:
--   NMMVA_DB_USER=nmmva_app   NMMVA_DB_PASSWORD=<contraseña larga y única>
-- =====================================================================================

-- 1) Migraciones: correrlas con una cuenta separada que SÍ puede hacer DDL (solo al desplegar).
CREATE USER IF NOT EXISTS 'nmmva_migrator'@'localhost' IDENTIFIED BY 'CAMBIAR_ESTA_CLAVE_1';
GRANT ALTER, CREATE, INDEX, SELECT, INSERT, UPDATE ON nmmva_bank.* TO 'nmmva_migrator'@'localhost';

-- 2) Cuenta de la aplicación en ejecución: sin DDL, sin DROP, sin acceso a otras bases.
CREATE USER IF NOT EXISTS 'nmmva_app'@'localhost' IDENTIFIED BY 'CAMBIAR_ESTA_CLAVE_2';
GRANT SELECT, INSERT, UPDATE ON nmmva_bank.usuarios            TO 'nmmva_app'@'localhost';
GRANT SELECT, INSERT         ON nmmva_bank.contratos_firmados  TO 'nmmva_app'@'localhost';
-- Bitácoras APPEND-ONLY: la app puede escribir y leer, pero NUNCA modificar ni borrar
-- (evidencia para No Repudio y contra "Indicator Removal", ATT&CK T1070).
GRANT SELECT, INSERT         ON nmmva_bank.logs_auditoria      TO 'nmmva_app'@'localhost';
GRANT SELECT, INSERT         ON nmmva_bank.auditoria_segura    TO 'nmmva_app'@'localhost';
-- Nota: las migraciones de la app (backend/app/migrations.py) necesitan DDL. En producción,
-- ejecútalas una vez con 'nmmva_migrator' y luego arranca la app con 'nmmva_app'.

FLUSH PRIVILEGES;
