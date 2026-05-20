from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    WAZUH_SERVER_API_PROTOCOL: str = "https"
    WAZUH_SERVER_API_HOST: str = "localhost"
    WAZUH_SERVER_API_PORT: str = "55000"
    WAZUH_SERVER_API_USERNAME: str = "wazuh"
    WAZUH_SERVER_API_PASSWORD: str = "wazuh"
    WAZUH_SERVER_AUTH_TOKEN_EXP_TIMEOUT: int = 900

    WAZUH_INDEXER_USER: str = "admin"
    WAZUH_INDEXER_PASSWORD: str = "?bk5+GvTVeKBtL7J5wcSMmenR8Hk+lue"
    WAZUH_INDEXER_PORT: str = "9200"

    TEST_LLM_MODEL: str | None = None
    TEST_LLM_API_KEY: str | None = None
    TEST_LLM_BASE_URL: str | None = None

    ATTRIBUTION_LLM_MODEL: str | None = None
    ATTRIBUTION_API_KEY: str | None = None
    ATTRIBUTION_LLM_BASE_URL: str | None = None

    LANGSMITH_TRACING: bool = False
    LANGSMITH_ENDPOINT: str | None = None
    LANGSMITH_API_KEY: str | None = None
    LANGSMITH_PROJECT: str | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

if __name__ == "__main__":
    print(settings)
    print(settings.WAZUH_SERVER_API_HOST)
