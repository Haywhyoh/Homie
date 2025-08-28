import { Injectable, Logger } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { State, LocalGovernmentArea, PostCategory } from '../entities';

@Injectable()
export class SeederService {
  private readonly logger = new Logger(SeederService.name);

  constructor(
    @InjectRepository(State)
    private stateRepository: Repository<State>,
    @InjectRepository(LocalGovernmentArea)
    private lgaRepository: Repository<LocalGovernmentArea>,
    @InjectRepository(PostCategory)
    private postCategoryRepository: Repository<PostCategory>,
  ) {}

  async seedAll(): Promise<void> {
    this.logger.log('Starting database seeding...');
    
    try {
      await this.seedStates();
      await this.seedLgas();
      await this.seedPostCategories();
      
      this.logger.log('Database seeding completed successfully');
    } catch (error) {
      this.logger.error('Database seeding failed', error);
      throw error;
    }
  }

  private async seedStates(): Promise<void> {
    this.logger.log('Seeding Nigerian states...');
    
    const existingStates = await this.stateRepository.count();
    if (existingStates > 0) {
      this.logger.log('States already exist, skipping...');
      return;
    }

    const nigerianStates = [
      { name: 'Abia', code: 'AB' },
      { name: 'Adamawa', code: 'AD' },
      { name: 'Akwa Ibom', code: 'AK' },
      { name: 'Anambra', code: 'AN' },
      { name: 'Bauchi', code: 'BA' },
      { name: 'Bayelsa', code: 'BY' },
      { name: 'Benue', code: 'BE' },
      { name: 'Borno', code: 'BO' },
      { name: 'Cross River', code: 'CR' },
      { name: 'Delta', code: 'DE' },
      { name: 'Ebonyi', code: 'EB' },
      { name: 'Edo', code: 'ED' },
      { name: 'Ekiti', code: 'EK' },
      { name: 'Enugu', code: 'EN' },
      { name: 'FCT', code: 'FC' },
      { name: 'Gombe', code: 'GO' },
      { name: 'Imo', code: 'IM' },
      { name: 'Jigawa', code: 'JI' },
      { name: 'Kaduna', code: 'KD' },
      { name: 'Kano', code: 'KN' },
      { name: 'Katsina', code: 'KT' },
      { name: 'Kebbi', code: 'KE' },
      { name: 'Kogi', code: 'KO' },
      { name: 'Kwara', code: 'KW' },
      { name: 'Lagos', code: 'LA' },
      { name: 'Nasarawa', code: 'NA' },
      { name: 'Niger', code: 'NI' },
      { name: 'Ogun', code: 'OG' },
      { name: 'Ondo', code: 'ON' },
      { name: 'Osun', code: 'OS' },
      { name: 'Oyo', code: 'OY' },
      { name: 'Plateau', code: 'PL' },
      { name: 'Rivers', code: 'RI' },
      { name: 'Sokoto', code: 'SO' },
      { name: 'Taraba', code: 'TA' },
      { name: 'Yobe', code: 'YO' },
      { name: 'Zamfara', code: 'ZA' },
    ];

    await this.stateRepository.save(nigerianStates);
    this.logger.log(`Seeded ${nigerianStates.length} Nigerian states`);
  }

  private async seedLgas(): Promise<void> {
    this.logger.log('Seeding Lagos LGAs...');
    
    const existingLgas = await this.lgaRepository.count();
    if (existingLgas > 0) {
      this.logger.log('LGAs already exist, skipping...');
      return;
    }

    // Get Lagos state
    const lagosState = await this.stateRepository.findOne({ where: { code: 'LA' } });
    if (!lagosState) {
      this.logger.error('Lagos state not found');
      return;
    }

    const lagosLgas = [
      'Agege',
      'Ajeromi-Ifelodun',
      'Alimosho',
      'Amuwo-Odofin',
      'Apapa',
      'Badagry',
      'Epe',
      'Eti-Osa',
      'Ibeju-Lekki',
      'Ifako-Ijaiye',
      'Ikeja',
      'Ikorodu',
      'Kosofe',
      'Lagos Island',
      'Lagos Mainland',
      'Mushin',
      'Ojo',
      'Oshodi-Isolo',
      'Shomolu',
      'Surulere',
    ].map(name => ({ name, stateId: lagosState.id }));

    await this.lgaRepository.save(lagosLgas);
    this.logger.log(`Seeded ${lagosLgas.length} Lagos LGAs`);
  }

  private async seedPostCategories(): Promise<void> {
    this.logger.log('Seeding post categories...');
    
    const existingCategories = await this.postCategoryRepository.count();
    if (existingCategories > 0) {
      this.logger.log('Post categories already exist, skipping...');
      return;
    }

    const categories = [
      {
        name: 'General',
        description: 'General community discussions',
        colorCode: '#6B7280',
      },
      {
        name: 'Safety & Security',
        description: 'Safety alerts and security discussions',
        colorCode: '#EF4444',
      },
      {
        name: 'Events',
        description: 'Community events and gatherings',
        colorCode: '#8B5CF6',
      },
      {
        name: 'Marketplace',
        description: 'Buy, sell, and trade items',
        colorCode: '#10B981',
      },
      {
        name: 'Lost & Found',
        description: 'Lost and found items',
        colorCode: '#F59E0B',
      },
      {
        name: 'Services',
        description: 'Local services and recommendations',
        colorCode: '#3B82F6',
      },
      {
        name: 'News & Updates',
        description: 'Local news and community updates',
        colorCode: '#06B6D4',
      },
      {
        name: 'Help & Support',
        description: 'Community help and support requests',
        colorCode: '#EC4899',
      },
    ];

    await this.postCategoryRepository.save(categories);
    this.logger.log(`Seeded ${categories.length} post categories`);
  }
}