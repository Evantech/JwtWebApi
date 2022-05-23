using System;
namespace Application
{
	public class User
	{
		public string username { get; set; } 
		public byte [] PasswordHash { get; set; }
		public byte [] PasswordSalt { get; set; }
	}
}

