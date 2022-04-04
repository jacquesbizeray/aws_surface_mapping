import sqlite3

# conectando...
conn = sqlite3.connect('/home/gitlab-runner/data/aws_surface_mapping/resultado.db')
#DEBUG CONFIG
# conn = sqlite3.connect('../resultado.db')

# definindo um cursor
cursor = conn.cursor()

# criando a tabela (schema)
cursor.execute("""
CREATE TABLE resultado (
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        instance_id TEXT,
        public_ip INTEGER,
        private_ip     INTEGER,
        region TEXT,
        owner_id TEXT,
        port INTEGER,
        protocol TEXT ,
        securitygroup TEXT 
);
""")

print('Tabela criada com sucesso.')
# desconectando...
conn.close()
