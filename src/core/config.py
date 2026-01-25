from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    WAZUH_SERVER_API_PROTOCOL: str = "https"
    WAZUH_SERVER_API_HOST: str = "localhost"
    WAZUH_SERVER_API_PORT: str = "55000"
    WAZUH_SERVER_API_USERNAME: str = "wazuh"
    WAZUH_SERVER_API_PASSWORD: str = "wazuh"
    WAZUH_SERVER_AUTH_TOKEN_EXP_TIMEOUT: int = 900

    TEST_LLM_MODEL: str | None
    TEST_LLM_API_KEY: str | None
    TEST_LLM_BASE_URL: str | None

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )


settings = Settings()

if __name__ == "__main__":
    print(settings)
    print(settings.WAZUH_SERVER_API_HOST)
