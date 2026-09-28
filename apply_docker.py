def modify_docker_compose():
    with open("docker-compose.yml", "r", encoding="utf-8") as f:
        content = f.read()

    if "redis:" not in content:
        redis_service = """
  redis:
    image: redis:alpine
    container_name: email_intelligence_redis
    ports:
      - "6379:6379"
    restart: unless-stopped
"""
        # insert before 'backend:'
        content = content.replace("  backend:", redis_service.lstrip("\n") + "\n  backend:")
        
    if "REDIS_URL=" not in content:
        content = content.replace("MONGO_URI=mongodb://mongodb:27017/email_intelligence_db", "MONGO_URI=mongodb://mongodb:27017/email_intelligence_db\n      - REDIS_URL=redis://redis:6379")
        
    if "depends_on:" in content and "redis" not in content.split("depends_on:")[1]:
        content = content.replace("depends_on:\n      - mongodb", "depends_on:\n      - mongodb\n      - redis")
        # Handle CRLF
        content = content.replace("depends_on:\r\n      - mongodb", "depends_on:\r\n      - mongodb\r\n      - redis")

    with open("docker-compose.yml", "w", encoding="utf-8") as f:
        f.write(content)

def modify_docker_compose_prod():
    with open("docker-compose.prod.yml", "r", encoding="utf-8") as f:
        content = f.read()

    if "redis:" not in content:
        redis_service = """
  redis:
    image: redis:alpine
    container_name: mailtrail_redis
    restart: unless-stopped
"""
        content = content.replace("  caddy:", redis_service.lstrip("\n") + "\n  caddy:")

    if "REDIS_URL=" not in content:
        content = content.replace("- MONGO_URI=${MONGO_URI}", "- MONGO_URI=${MONGO_URI}\n      - REDIS_URL=redis://redis:6379")
        
    if "depends_on:" not in content.split("caddy:")[0]:
        depends = """    depends_on:
      - redis"""
        content = content.replace("    expose:", depends + "\n    expose:")

    with open("docker-compose.prod.yml", "w", encoding="utf-8") as f:
        f.write(content)

def modify_env_example():
    with open(".env.example", "r", encoding="utf-8") as f:
        content = f.read()

    if "REDIS_URL=" not in content:
        content += "\n# Real-time WebSocket multi-instance sync\nREDIS_URL=redis://localhost:6379\n"
        
    with open(".env.example", "w", encoding="utf-8") as f:
        f.write(content)

modify_docker_compose()
modify_docker_compose_prod()
modify_env_example()
