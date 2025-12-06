from typing import List, Dict, Any, Type, Optional, Union
from pydantic import BaseModel, Field

class AgentInput(BaseModel):
    description: str
    type: str = "string"
    required: bool = True

class AgentOutput(BaseModel):
    output_name: str
    description: str
    schema_model: Type[BaseModel]
    
    class Config:
        arbitrary_types_allowed = True

class AgentToolConfig(BaseModel):
    tools: List[str] = Field(default_factory=list)

class AgentPromptConfig(BaseModel):
    system_prompt: str
    initial_query_template: str

class AgentDefinition(BaseModel):
    name: str
    description: str
    prompt_config: AgentPromptConfig
    tool_config: AgentToolConfig = Field(default_factory=AgentToolConfig)
    input_config: Dict[str, AgentInput]
    output_config: Optional[AgentOutput] = None
