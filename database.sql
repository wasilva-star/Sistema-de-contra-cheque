-- ============================================================
--  SISTEMA DE CONTRACHEQUES — IECPN
--  Script de criação do banco de dados MySQL
-- ============================================================

CREATE DATABASE IF NOT EXISTS iecpn_contracheques
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE iecpn_contracheques;

-- ------------------------------------------------------------
-- TABELA: usuarios
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS usuarios (
  id            INT UNSIGNED    NOT NULL AUTO_INCREMENT,
  username      VARCHAR(120)    NOT NULL,
  password_hash VARCHAR(255)    NOT NULL,
  role          ENUM('superadmin','admin','rh','colaborador') NOT NULL DEFAULT 'colaborador',
  matricula     VARCHAR(40)     NULL,
  cpf           CHAR(11)        NULL COMMENT 'somente dígitos',
  nome_completo VARCHAR(200)    NULL,
  ativo         TINYINT(1)      NOT NULL DEFAULT 1,
  criado_em     DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
  atualizado_em DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  PRIMARY KEY (id),
  UNIQUE KEY uq_username  (username),
  UNIQUE KEY uq_cpf       (cpf),
  UNIQUE KEY uq_matricula (matricula),
  INDEX idx_role (role)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- TABELA: contracheques
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS contracheques (
  id               INT UNSIGNED  NOT NULL AUTO_INCREMENT,
  usuario_id       INT UNSIGNED  NOT NULL,
  mes_referencia   VARCHAR(40)   NOT NULL COMMENT 'Ex.: Outubro/2025',
  nome_arquivo     VARCHAR(255)  NOT NULL,
  arquivo_dados    LONGBLOB      NOT NULL COMMENT 'PDF em base64',
  visualizado      TINYINT(1)    NOT NULL DEFAULT 0,
  data_visualizacao DATETIME     NULL,
  enviado_por      INT UNSIGNED  NULL COMMENT 'ID do admin que enviou',
  criado_em        DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (id),
  CONSTRAINT fk_cc_usuario  FOREIGN KEY (usuario_id)  REFERENCES usuarios(id) ON DELETE CASCADE,
  CONSTRAINT fk_cc_enviador FOREIGN KEY (enviado_por) REFERENCES usuarios(id) ON DELETE SET NULL,
  INDEX idx_usuario_id  (usuario_id),
  INDEX idx_visualizado (visualizado)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- TABELA: log_acoes  (auditoria)
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS log_acoes (
  id          INT UNSIGNED NOT NULL AUTO_INCREMENT,
  usuario_id  INT UNSIGNED NULL,
  acao        VARCHAR(100) NOT NULL,
  descricao   TEXT         NULL,
  ip          VARCHAR(45)  NULL,
  criado_em   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,

  PRIMARY KEY (id),
  CONSTRAINT fk_log_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL,
  INDEX idx_log_usuario (usuario_id),
  INDEX idx_log_acao    (acao)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ------------------------------------------------------------
-- SUPERADMIN padrão  (senha: teste123  — TROQUE EM PRODUÇÃO)
-- ------------------------------------------------------------
INSERT IGNORE INTO usuarios (username, password_hash, role, nome_completo)
VALUES (
  'superadmin',
  '', -- teste123
  'superadmin',
  'Super Administrador'
);
