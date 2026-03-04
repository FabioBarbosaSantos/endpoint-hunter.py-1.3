# endpoint-hunter.py-1.3

1. Clone o repositório
```bash
git clone https://github.com/FabioBarbosaSantos/endpoint-hunter.py-1.3.git
cd endpoint-hunter.py-1.3
```
2. Crie e ative um ambiente virtual (importante no Ubuntu 24.04+)
```bash
python3 -m venv venv
source venv/bin/activate
```
3. Instale as dependências Python
```bash
pip install --upgrade pip
pip install -r requirements.txt
```
4. Instale o browser Chromium do Playwright
```bash
playwright install chromium
```

Exemples
```bash
# Modo básico
python endpoint-hunter.py -u https://juice-shop.herokuapp.com

# Com delay para evitar WAF (recomendado em produção)
python endpoint-hunter.py -u https://target.com --delay 0.3 --threads 10

# Modo mais agressivo
python endpoint-hunter.py -u https://target.com --threads 30 --delay 0.1 --aggressive

# Salvar resultados
python endpoint-hunter.py -u https://target.com --output endpoints.txt

# Modo relaxed (captura mais caminhos suspeitos)
python endpoint-hunter.py -u https://target.com --relaxed

# Escopo extra (inclui subdomínios ou domínios relacionados)
python endpoint-hunter.py -u https://app.target.com --scope target.com --scope api.target.com
```

Options
```bash
-u, --url               URL alvo (obrigatório)                  [ex: https://example.com]
-t, --threads           Número de threads (padrão: 15)          [5=shy, 15=normal, 30=fast, 50+=aggressive]
--delay                 Delay em segundos entre requests        [0.0–1.0, recomendado 0.2–0.5]
--output                Arquivo para salvar resultados          [ex: results.txt]
--aggressive            Aumenta threads para 40+
--timeout               Timeout por request (padrão: 12s)
--retries               Tentativas em caso de falha (padrão: 2)
--relaxed               Modo relaxado: aceita mais caminhos
--scope                 Domínio extra permitido (pode repetir)
--verbose               Mostra mais logs
--no-color              Desativa cores no terminal
```
