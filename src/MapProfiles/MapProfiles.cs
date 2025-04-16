namespace Aplication.MapProfiles
{
    using Aplication.Models;
    using AutoMapper;

    public class MapProfiles : Profile
    {
        public MapProfiles()
        {
            CreateMap<Usuario, ObtenerusuarioDto>().ReverseMap();
            CreateMap<Usuario, UsuarioRegisterDto>().ReverseMap();

        }
    }
}