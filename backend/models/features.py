from typing import Literal

from pydantic import BaseModel, Field


class WgAddRequest(BaseModel):
    client_name: str = Field(min_length=1, max_length=15)


class WgRenameRequest(BaseModel):
    old_name: str = Field(min_length=1, max_length=15)
    new_name: str = Field(min_length=1, max_length=15)


class WgNameRequest(BaseModel):
    client_name: str = Field(min_length=1, max_length=15)


class WgParamsPutRequest(BaseModel):
    params: dict[str, str]
    apply_to_clients: bool = False


class ZapretAddRequest(BaseModel):
    list_name: str = Field(min_length=1)
    sites: list[str] = Field(min_length=1)
    scope: Literal["domains", "ipset"] | None = None


class ZapretCheckRequest(BaseModel):
    site: str = Field(min_length=1)


class DnsBulkKeywordsRequest(BaseModel):
    text: str = Field(min_length=1)


class DnsKeywordRequest(BaseModel):
    keyword: str = Field(min_length=1)
